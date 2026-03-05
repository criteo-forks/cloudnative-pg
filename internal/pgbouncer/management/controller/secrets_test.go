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

package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	apiv1 "github.com/cloudnative-pg/cloudnative-pg/api/v1"
	"github.com/cloudnative-pg/cloudnative-pg/internal/scheme"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("getSecrets tests", func() {
	var (
		k8sClient ctrlclient.WithWatch
		pooler    *apiv1.Pooler
	)

	BeforeEach(func() {
		k8sClient, pooler = buildTestEnv()
	})

	Context("when status is not populated yet", func() {
		It("should return error", func(ctx context.Context) {
			pooler.Status.Secrets = nil

			_, err := getSecrets(ctx, k8sClient, pooler)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("status not populated yet"))
		})
	})

	Context("when all secrets are found", func() {
		It("should return secrets without error", func(ctx context.Context) {
			res, err := getSecrets(ctx, k8sClient, pooler)

			Expect(err).ToNot(HaveOccurred())
			Expect(res.ClientCA.Name).To(Equal(clientCAName))
			Expect(res.ClientTLS.Name).To(Equal(clientTLSName))
			Expect(res.ServerCA.Name).To(Equal(serverCAName))
			Expect(res.AuthQuery).To(BeNil())
		})
	})

	Context("when a secret is not found", func() {
		BeforeEach(func() {
			pooler.Status.Secrets.ServerCA = apiv1.SecretVersion{Name: "nonexistent"}
		})

		It("should return error", func(ctx context.Context) {
			_, err := getSecrets(ctx, k8sClient, pooler)

			Expect(err).To(HaveOccurred())
		})
	})

	Context("LDAP bind password secret", func() {
		const ldapSecretName = "ldap-bind-secret"

		buildLDAPEnv := func(secretData map[string][]byte) (ctrlclient.WithWatch, *apiv1.Pooler) {
			ldapSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: ldapSecretName, Namespace: "default"},
				Data:       secretData,
			}
			authQuerySecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: authQueryName, Namespace: "default"},
			}
			serverCASecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: serverCAName, Namespace: "default"},
			}
			serverCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: serverTLSName, Namespace: "default"},
			}
			clientCASecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: clientCAName, Namespace: "default"},
			}

			p := &apiv1.Pooler{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pooler-ldap", Namespace: "default"},
				Spec: apiv1.PoolerSpec{
					PgBouncer: &apiv1.PgBouncerSpec{
						AuthQuerySecret: &apiv1.LocalObjectReference{Name: authQueryName},
						LDAP: &apiv1.LDAPConfig{
							Server: "ldap.example.com",
							BindSearchAuth: &apiv1.LDAPBindSearchAuth{
								BaseDN: "dc=example,dc=com",
								BindPassword: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: ldapSecretName},
									Key:                  "password",
								},
							},
						},
					},
					Cluster: apiv1.LocalObjectReference{Name: "cluster"},
				},
				Status: apiv1.PoolerStatus{
					Secrets: &apiv1.PoolerSecrets{
						ServerCA:  apiv1.SecretVersion{Name: serverCAName},
						ServerTLS: apiv1.SecretVersion{Name: serverTLSName},
						ClientCA:  apiv1.SecretVersion{Name: clientCAName},
						ClientTLS: apiv1.SecretVersion{Name: clientTLSName},
					},
				},
			}

			c := fake.NewClientBuilder().WithScheme(scheme.BuildWithAllKnownScheme()).
				WithObjects(p, ldapSecret, authQuerySecret, serverCASecret, serverCertSecret, clientCASecret).
				Build()
			return c, p
		}

		It("should load the LDAP bind password from the secret", func(ctx context.Context) {
			c, p := buildLDAPEnv(map[string][]byte{"password": []byte("s3cret")})
			res, err := getSecrets(ctx, c, p)

			Expect(err).ToNot(HaveOccurred())
			Expect(res.LDAPBindPassword).To(Equal("s3cret"))
		})

		It("should fail when the key is missing from the secret", func(ctx context.Context) {
			c, p := buildLDAPEnv(map[string][]byte{"wrong-key": []byte("s3cret")})
			_, err := getSecrets(ctx, c, p)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("key \"password\" not found"))
		})

		It("should fail when the secret name is empty", func(ctx context.Context) {
			c, p := buildLDAPEnv(map[string][]byte{"password": []byte("s3cret")})
			p.Spec.PgBouncer.LDAP.BindSearchAuth.BindPassword.Name = ""
			_, err := getSecrets(ctx, c, p)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("secret name is empty"))
		})

		It("should fail when the LDAP secret does not exist", func(ctx context.Context) {
			c, p := buildLDAPEnv(map[string][]byte{"password": []byte("s3cret")})
			p.Spec.PgBouncer.LDAP.BindSearchAuth.BindPassword.Name = "nonexistent-secret"
			_, err := getSecrets(ctx, c, p)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("while getting LDAP bind password secret"))
		})
	})
})
