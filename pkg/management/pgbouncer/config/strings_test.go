/*
Copyright © contributors to CloudNativePG, established as
CloudNativePG a Series of LF Projects, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/cloudnative-pg/cloudnative-pg/api/v1"
	"github.com/cloudnative-pg/cloudnative-pg/pkg/certs"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PgBouncer configuration", func() {
	It("can build valid configurations", func() {
		validParams := map[string]string{
			"verbose":                  "10",
			ignoreStartupParametersKey: "test",
		}
		params := buildPgBouncerParameters(validParams)
		Expect(params[ignoreStartupParametersKey]).To(ContainSubstring("test"))
		Expect(params[ignoreStartupParametersKey]).
			To(ContainSubstring(defaultPgBouncerParameters[ignoreStartupParametersKey]))
		Expect(params["verbose"]).To(BeEquivalentTo("10"))
		Expect(params["logstats"]).To(BeEquivalentTo(defaultPgBouncerParameters["logstats"]))
	})

	It("can escape values", func() {
		validParams := map[string]string{
			"verbose":             "10\npool_mode: test",
			"autodb_idle_timeout": "10\\npid_file: test",
		}
		params := stringifyPgBouncerParameters(buildPgBouncerParameters(validParams))
		Expect(params).NotTo(MatchRegexp("^pool_mode.*"))
		Expect(params).NotTo(MatchRegexp("^pid_file.*"))
	})
})

var _ = Describe("BuildConfigurationFiles with LDAP", func() {
	buildTestSecrets := func() *Secrets {
		return &Secrets{
			AuthQuery: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "auth-query"},
				Type:       corev1.SecretTypeBasicAuth,
				Data: map[string][]byte{
					"username": []byte("pgbouncer"),
					"password": []byte("pass"),
				},
			},
			ServerCA: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "server-ca"},
				Data:       map[string][]byte{certs.CACertKey: []byte("ca-cert")},
			},
			ClientCA: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "client-ca"},
				Data:       map[string][]byte{certs.CACertKey: []byte("ca-cert")},
			},
			ClientTLS: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "client-tls"},
				Data: map[string][]byte{
					certs.TLSCertKey:       []byte("tls-cert"),
					certs.TLSPrivateKeyKey: []byte("tls-key"),
				},
			},
		}
	}

	It("generates pg_hba.conf with LDAP rules when LDAP is configured", func() {
		pooler := &apiv1.Pooler{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pooler", Namespace: "default"},
			Spec: apiv1.PoolerSpec{
				Cluster: apiv1.LocalObjectReference{Name: "my-cluster"},
				Type:    apiv1.PoolerTypeRW,
				PgBouncer: &apiv1.PgBouncerSpec{
					PoolMode: apiv1.PgBouncerPoolModeSession,
					LDAP: &apiv1.LDAPConfig{
						Server: "ldap.example.com",
						Port:   636,
						Scheme: apiv1.LDAPSchemeLDAPS,
						BindSearchAuth: &apiv1.LDAPBindSearchAuth{
							BaseDN:          "dc=example,dc=com",
							BindDN:          "cn=admin,dc=example,dc=com",
							SearchAttribute: "sAMAccountName",
						},
					},
				},
			},
		}

		secrets := buildTestSecrets()
		secrets.LDAPBindPassword = "s3cret"

		files, err := BuildConfigurationFiles(pooler, secrets)
		Expect(err).ToNot(HaveOccurred())

		hbaContent := string(files[ConfigsDir+"/pg_hba.conf"])
		Expect(hbaContent).To(ContainSubstring("local pgbouncer pgbouncer peer"))
		Expect(hbaContent).To(ContainSubstring("host all all 0.0.0.0/0 ldap"))
		Expect(hbaContent).To(ContainSubstring("host all all ::/0 ldap"))
		Expect(hbaContent).To(ContainSubstring(`ldapserver="ldap.example.com"`))
		Expect(hbaContent).To(ContainSubstring(`ldapbasedn="dc=example,dc=com"`))
		Expect(hbaContent).To(ContainSubstring(`ldapbindpasswd="s3cret"`))
		Expect(hbaContent).To(ContainSubstring(`ldapsearchattribute="sAMAccountName"`))

		// PgBouncer does not allow LDAP together with auth_query; when LDAP is used, auth_query must be omitted.
		iniContent := string(files[ConfigsDir+"/pgbouncer.ini"])
		Expect(iniContent).NotTo(ContainSubstring("auth_query"))
	})

	It("generates pg_hba.conf with md5 when LDAP is not configured", func() {
		pooler := &apiv1.Pooler{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pooler", Namespace: "default"},
			Spec: apiv1.PoolerSpec{
				Cluster: apiv1.LocalObjectReference{Name: "my-cluster"},
				Type:    apiv1.PoolerTypeRW,
				PgBouncer: &apiv1.PgBouncerSpec{
					PoolMode: apiv1.PgBouncerPoolModeSession,
				},
			},
		}

		files, err := BuildConfigurationFiles(pooler, buildTestSecrets())
		Expect(err).ToNot(HaveOccurred())

		hbaContent := string(files[ConfigsDir+"/pg_hba.conf"])
		Expect(hbaContent).To(ContainSubstring("host all all 0.0.0.0/0 md5"))
		Expect(hbaContent).To(ContainSubstring("host all all ::/0 md5"))
		Expect(hbaContent).NotTo(ContainSubstring("ldap"))
	})

	It("generates pg_hba.conf with md5 when LDAP struct is set but no auth mode specified", func() {
		pooler := &apiv1.Pooler{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pooler", Namespace: "default"},
			Spec: apiv1.PoolerSpec{
				Cluster: apiv1.LocalObjectReference{Name: "my-cluster"},
				Type:    apiv1.PoolerTypeRW,
				PgBouncer: &apiv1.PgBouncerSpec{
					PoolMode: apiv1.PgBouncerPoolModeSession,
					LDAP: &apiv1.LDAPConfig{
						Server: "ldap.example.com",
					},
				},
			},
		}

		files, err := BuildConfigurationFiles(pooler, buildTestSecrets())
		Expect(err).ToNot(HaveOccurred())

		hbaContent := string(files[ConfigsDir+"/pg_hba.conf"])
		Expect(hbaContent).To(ContainSubstring("host all all 0.0.0.0/0 md5"))
		Expect(hbaContent).To(ContainSubstring("host all all ::/0 md5"))
		Expect(hbaContent).NotTo(ContainSubstring("ldap"))
	})

	It("returns error when ServerCA is nil", func() {
		pooler := &apiv1.Pooler{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pooler", Namespace: "default"},
			Spec: apiv1.PoolerSpec{
				Cluster: apiv1.LocalObjectReference{Name: "my-cluster"},
				Type:    apiv1.PoolerTypeRW,
				PgBouncer: &apiv1.PgBouncerSpec{
					PoolMode: apiv1.PgBouncerPoolModeSession,
				},
			},
		}

		secrets := buildTestSecrets()
		secrets.ServerCA = nil

		_, err := BuildConfigurationFiles(pooler, secrets)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("server CA secret not yet available"))
	})
})

var _ = Describe("LDAP HBA options", func() {
	It("builds options for simple bind mode", func() {
		ldap := &apiv1.LDAPConfig{
			Server: "ldap.example.com",
			Port:   389,
			BindAsAuth: &apiv1.LDAPBindAsAuth{
				Prefix: "cn=",
				Suffix: ",dc=example,dc=com",
			},
		}
		opts := buildLDAPHBAOptions(ldap, "")
		Expect(opts).To(ContainSubstring(`ldapserver="ldap.example.com"`))
		Expect(opts).To(ContainSubstring("ldapport=389"))
		Expect(opts).To(ContainSubstring(`ldapprefix="cn="`))
		Expect(opts).To(ContainSubstring(`ldapsuffix=",dc=example,dc=com"`))
		Expect(opts).NotTo(ContainSubstring("ldapbasedn"))
	})

	It("builds options for search+bind mode", func() {
		ldap := &apiv1.LDAPConfig{
			Server: "ldap.example.com",
			Port:   636,
			Scheme: apiv1.LDAPSchemeLDAPS,
			BindSearchAuth: &apiv1.LDAPBindSearchAuth{
				BaseDN:          "dc=example,dc=com",
				BindDN:          "cn=admin,dc=example,dc=com",
				SearchAttribute: "uid",
			},
		}
		opts := buildLDAPHBAOptions(ldap, "s3cret")
		Expect(opts).To(ContainSubstring(`ldapserver="ldap.example.com"`))
		Expect(opts).To(ContainSubstring("ldapport=636"))
		Expect(opts).To(ContainSubstring(`ldapscheme="ldaps"`))
		Expect(opts).To(ContainSubstring(`ldapbasedn="dc=example,dc=com"`))
		Expect(opts).To(ContainSubstring(`ldapbinddn="cn=admin,dc=example,dc=com"`))
		Expect(opts).To(ContainSubstring(`ldapbindpasswd="s3cret"`))
		Expect(opts).To(ContainSubstring(`ldapsearchattribute="uid"`))
		Expect(opts).NotTo(ContainSubstring("ldapprefix"))
	})

	It("includes TLS option when enabled", func() {
		ldap := &apiv1.LDAPConfig{
			Server: "ldap.example.com",
			TLS:    true,
			BindAsAuth: &apiv1.LDAPBindAsAuth{
				Prefix: "uid=",
				Suffix: ",ou=people,dc=example,dc=com",
			},
		}
		opts := buildLDAPHBAOptions(ldap, "")
		Expect(opts).To(ContainSubstring("ldaptls=1"))
	})

	It("includes search filter when specified", func() {
		ldap := &apiv1.LDAPConfig{
			Server: "ldap.example.com",
			BindSearchAuth: &apiv1.LDAPBindSearchAuth{
				BaseDN:       "dc=example,dc=com",
				BindDN:       "cn=admin,dc=example,dc=com",
				SearchFilter: "(memberOf=cn=dbusers,ou=groups,dc=example,dc=com)",
			},
		}
		opts := buildLDAPHBAOptions(ldap, "pass")
		Expect(opts).To(ContainSubstring("ldapsearchfilter="))
		Expect(opts).To(ContainSubstring("memberOf"))
	})

	It("handles minimal configuration with only server", func() {
		ldap := &apiv1.LDAPConfig{
			Server: "ldap.example.com",
		}
		opts := buildLDAPHBAOptions(ldap, "")
		Expect(opts).To(Equal(`ldapserver="ldap.example.com"`))
	})
})

var _ = Describe("quoteHbaLiteral", func() {
	It("wraps values in double quotes", func() {
		Expect(quoteHbaLiteral("test")).To(Equal(`"test"`))
	})

	It("escapes double quotes inside values", func() {
		Expect(quoteHbaLiteral(`val"ue`)).To(Equal(`"val""ue"`))
	})
})
