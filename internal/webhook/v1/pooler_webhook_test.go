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

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/cloudnative-pg/cloudnative-pg/api/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Pooler validation", func() {
	var v *PoolerCustomValidator
	BeforeEach(func() {
		v = &PoolerCustomValidator{}
	})

	It("doesn't allow specifying authQuerySecret without any authQuery", func() {
		pooler := &apiv1.Pooler{
			Spec: apiv1.PoolerSpec{
				PgBouncer: &apiv1.PgBouncerSpec{
					AuthQuerySecret: &apiv1.LocalObjectReference{
						Name: "test",
					},
				},
			},
		}

		Expect(v.validatePgBouncer(pooler)).NotTo(BeEmpty())
	})

	It("doesn't allow specifying authQuery without any authQuerySecret", func() {
		pooler := &apiv1.Pooler{
			Spec: apiv1.PoolerSpec{
				PgBouncer: &apiv1.PgBouncerSpec{
					AuthQuery: "test",
				},
			},
		}

		Expect(v.validatePgBouncer(pooler)).NotTo(BeEmpty())
	})

	It("allows having both authQuery and authQuerySecret", func() {
		pooler := &apiv1.Pooler{
			Spec: apiv1.PoolerSpec{
				PgBouncer: &apiv1.PgBouncerSpec{
					AuthQuery: "test",
					AuthQuerySecret: &apiv1.LocalObjectReference{
						Name: "test",
					},
				},
			},
		}

		Expect(v.validatePgBouncer(pooler)).To(BeEmpty())
	})

	It("allows the autoconfiguration mode", func() {
		pooler := &apiv1.Pooler{
			Spec: apiv1.PoolerSpec{
				PgBouncer: &apiv1.PgBouncerSpec{},
			},
		}

		Expect(v.validatePgBouncer(pooler)).To(BeEmpty())
	})

	It("doesn't allow not specifying a cluster name", func() {
		pooler := &apiv1.Pooler{
			Spec: apiv1.PoolerSpec{
				Cluster: apiv1.LocalObjectReference{Name: ""},
			},
		}
		Expect(v.validateCluster(pooler)).NotTo(BeEmpty())
	})

	It("doesn't allow to have a pooler with the same name of the cluster", func() {
		pooler := &apiv1.Pooler{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
			Spec: apiv1.PoolerSpec{
				Cluster: apiv1.LocalObjectReference{
					Name: "test",
				},
			},
		}
		Expect(v.validateCluster(pooler)).NotTo(BeEmpty())
	})

	It("doesn't complain when specifying a cluster name", func() {
		pooler := &apiv1.Pooler{
			Spec: apiv1.PoolerSpec{
				Cluster: apiv1.LocalObjectReference{Name: "cluster-example"},
			},
		}
		Expect(v.validateCluster(pooler)).To(BeEmpty())
	})

	It("does complain when given a fixed parameter", func() {
		pooler := &apiv1.Pooler{
			Spec: apiv1.PoolerSpec{
				PgBouncer: &apiv1.PgBouncerSpec{
					Parameters: map[string]string{"pool_mode": "test"},
				},
			},
		}
		Expect(v.validatePgbouncerGenericParameters(pooler)).NotTo(BeEmpty())
	})

	It("does not complain when given a valid parameter", func() {
		pooler := &apiv1.Pooler{
			Spec: apiv1.PoolerSpec{
				PgBouncer: &apiv1.PgBouncerSpec{
					Parameters: map[string]string{"verbose": "10"},
				},
			},
		}
		Expect(v.validatePgbouncerGenericParameters(pooler)).To(BeEmpty())
	})

	Context("LDAP validation", func() {
		It("accepts a valid LDAP bind-as configuration", func() {
			pooler := &apiv1.Pooler{
				Spec: apiv1.PoolerSpec{
					PgBouncer: &apiv1.PgBouncerSpec{
						LDAP: &apiv1.LDAPConfig{
							Server: "ldap.example.com",
							BindAsAuth: &apiv1.LDAPBindAsAuth{
								Prefix: "cn=",
								Suffix: ",dc=example,dc=com",
							},
						},
					},
				},
			}
			Expect(v.validatePgBouncerLDAP(pooler)).To(BeEmpty())
		})

		It("accepts a valid LDAP search+bind configuration", func() {
			pooler := &apiv1.Pooler{
				Spec: apiv1.PoolerSpec{
					PgBouncer: &apiv1.PgBouncerSpec{
						LDAP: &apiv1.LDAPConfig{
							Server: "ldap.example.com",
							BindSearchAuth: &apiv1.LDAPBindSearchAuth{
								BaseDN: "dc=example,dc=com",
								BindDN: "cn=admin,dc=example,dc=com",
								BindPassword: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: "ldap-secret"},
									Key:                  "password",
								},
							},
						},
					},
				},
			}
			Expect(v.validatePgBouncerLDAP(pooler)).To(BeEmpty())
		})

		It("rejects LDAP with server only and no auth mode", func() {
			pooler := &apiv1.Pooler{
				Spec: apiv1.PoolerSpec{
					PgBouncer: &apiv1.PgBouncerSpec{
						LDAP: &apiv1.LDAPConfig{
							Server: "ldap.example.com",
						},
					},
				},
			}
			errs := v.validatePgBouncerLDAP(pooler)
			Expect(errs).NotTo(BeEmpty())
			Expect(errs[0].Detail).To(ContainSubstring("bindAsAuth or bindSearchAuth"))
		})

		It("rejects LDAP with empty server", func() {
			pooler := &apiv1.Pooler{
				Spec: apiv1.PoolerSpec{
					PgBouncer: &apiv1.PgBouncerSpec{
						LDAP: &apiv1.LDAPConfig{
							Server: "",
							BindAsAuth: &apiv1.LDAPBindAsAuth{
								Prefix: "cn=",
								Suffix: ",dc=example,dc=com",
							},
						},
					},
				},
			}
			Expect(v.validatePgBouncerLDAP(pooler)).NotTo(BeEmpty())
		})

		It("rejects LDAP with both bindAsAuth and bindSearchAuth", func() {
			pooler := &apiv1.Pooler{
				Spec: apiv1.PoolerSpec{
					PgBouncer: &apiv1.PgBouncerSpec{
						LDAP: &apiv1.LDAPConfig{
							Server:     "ldap.example.com",
							BindAsAuth: &apiv1.LDAPBindAsAuth{Prefix: "cn="},
							BindSearchAuth: &apiv1.LDAPBindSearchAuth{
								BaseDN: "dc=example,dc=com",
								BindPassword: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: "ldap-secret"},
									Key:                  "password",
								},
							},
						},
					},
				},
			}
			Expect(v.validatePgBouncerLDAP(pooler)).NotTo(BeEmpty())
		})

		It("rejects search+bind without bindPassword", func() {
			pooler := &apiv1.Pooler{
				Spec: apiv1.PoolerSpec{
					PgBouncer: &apiv1.PgBouncerSpec{
						LDAP: &apiv1.LDAPConfig{
							Server: "ldap.example.com",
							BindSearchAuth: &apiv1.LDAPBindSearchAuth{
								BaseDN: "dc=example,dc=com",
								BindDN: "cn=admin,dc=example,dc=com",
							},
						},
					},
				},
			}
			Expect(v.validatePgBouncerLDAP(pooler)).NotTo(BeEmpty())
		})

		It("rejects search+bind with bindPassword missing secret name", func() {
			pooler := &apiv1.Pooler{
				Spec: apiv1.PoolerSpec{
					PgBouncer: &apiv1.PgBouncerSpec{
						LDAP: &apiv1.LDAPConfig{
							Server: "ldap.example.com",
							BindSearchAuth: &apiv1.LDAPBindSearchAuth{
								BaseDN: "dc=example,dc=com",
								BindDN: "cn=admin,dc=example,dc=com",
								BindPassword: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: ""},
									Key:                  "password",
								},
							},
						},
					},
				},
			}
			errs := v.validatePgBouncerLDAP(pooler)
			Expect(errs).NotTo(BeEmpty())
			Expect(errs[0].Field).To(ContainSubstring("bindPassword.name"))
		})

		It("passes validation when no LDAP is configured", func() {
			pooler := &apiv1.Pooler{
				Spec: apiv1.PoolerSpec{
					PgBouncer: &apiv1.PgBouncerSpec{},
				},
			}
			Expect(v.validatePgBouncerLDAP(pooler)).To(BeEmpty())
		})
	})
})
