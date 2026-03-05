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
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime/pkg/client"

	apiv1 "github.com/cloudnative-pg/cloudnative-pg/api/v1"
	"github.com/cloudnative-pg/cloudnative-pg/pkg/management/pgbouncer/config"
)

func secretKeys(data map[string][]byte) []string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// getSecrets loads the data needed to generate the configuration
// from Kubernetes and a Pooler resource
func getSecrets(ctx context.Context, client ctrl.Client, pooler *apiv1.Pooler) (*config.Secrets, error) {
	if pooler.Status.Secrets == nil {
		return nil, fmt.Errorf("status not populated yet")
	}

	result := &config.Secrets{}

	var (
		authQuerySecret corev1.Secret
		serverCASecret  corev1.Secret
		clientTLSSecret corev1.Secret
		clientCASecret  corev1.Secret
	)

	if pooler.Status.Secrets.ServerTLS.Name == "" {
		authQuerySecretName := pooler.GetAuthQuerySecretName()
		if err := client.Get(ctx,
			types.NamespacedName{
				Name:      authQuerySecretName,
				Namespace: pooler.Namespace,
			},
			&authQuerySecret); err != nil {
			return nil, fmt.Errorf("while getting auth query secret: %w", err)
		}
		result.AuthQuery = &authQuerySecret
	}

	if pooler.Status.Secrets.ServerTLS.Name != "" {
		var serverTLSSecret corev1.Secret
		if err := client.Get(ctx,
			types.NamespacedName{Name: pooler.Status.Secrets.ServerTLS.Name, Namespace: pooler.Namespace},
			&serverTLSSecret); err != nil {
			return nil, fmt.Errorf("while getting server TLS secret: %w", err)
		}
		result.ServerTLS = &serverTLSSecret
	}

	if pooler.Status.Secrets.ServerCA.Name != "" {
		if err := client.Get(ctx,
			types.NamespacedName{Name: pooler.Status.Secrets.ServerCA.Name, Namespace: pooler.Namespace},
			&serverCASecret); err != nil {
			return nil, fmt.Errorf("while getting server CA secret: %w", err)
		}
		result.ServerCA = &serverCASecret
	}

	if pooler.Status.Secrets.ClientTLS.Name != "" {
		if err := client.Get(ctx,
			types.NamespacedName{Name: pooler.Status.Secrets.ClientTLS.Name, Namespace: pooler.Namespace},
			&clientTLSSecret); err != nil {
			return nil, fmt.Errorf("while getting client TLS secret: %w", err)
		}
		result.ClientTLS = &clientTLSSecret
	}

	if pooler.Status.Secrets.ClientCA.Name != "" {
		if err := client.Get(ctx,
			types.NamespacedName{Name: pooler.Status.Secrets.ClientCA.Name, Namespace: pooler.Namespace},
			&clientCASecret); err != nil {
			return nil, fmt.Errorf("while getting client CA secret: %w", err)
		}
		result.ClientCA = &clientCASecret
	}

	if pooler.Spec.PgBouncer != nil &&
		pooler.Spec.PgBouncer.LDAP != nil &&
		pooler.Spec.PgBouncer.LDAP.BindSearchAuth != nil &&
		pooler.Spec.PgBouncer.LDAP.BindSearchAuth.BindPassword != nil {
		bindPasswordRef := pooler.Spec.PgBouncer.LDAP.BindSearchAuth.BindPassword
		if bindPasswordRef.Name == "" {
			return nil, fmt.Errorf("LDAP bind password secret name is empty")
		}
		var ldapSecret corev1.Secret
		if err := client.Get(ctx, types.NamespacedName{
			Name:      bindPasswordRef.Name,
			Namespace: pooler.Namespace,
		}, &ldapSecret); err != nil {
			return nil, fmt.Errorf("while getting LDAP bind password secret %q: %w", bindPasswordRef.Name, err)
		}
		key := bindPasswordRef.Key
		passwordData, ok := ldapSecret.Data[key]
		if !ok {
			return nil, fmt.Errorf(
				"key %q not found in LDAP bind password secret %q (available keys: %v)",
				key, bindPasswordRef.Name, secretKeys(ldapSecret.Data))
		}
		result.LDAPBindPassword = string(passwordData)
	}

	return result, nil
}
