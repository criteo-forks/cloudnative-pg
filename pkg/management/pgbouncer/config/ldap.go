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
	"fmt"
	"net/url"
	"strings"

	apiv1 "github.com/cloudnative-pg/cloudnative-pg/api/v1"
)

// LDAPBindPasswordMountDir is the directory where the LDAP bind password Secret
// is mounted in the PgBouncer Pod. Used by the operator to add the volume;
// PgBouncer config references LDAPBindPasswordMountDir/LDAPBindPasswordFileName.
const LDAPBindPasswordMountDir = "/etc/pgbouncer-ldap"

// LDAPBindPasswordFileName is the file name of the mounted bind password in the Pod.
const LDAPBindPasswordFileName = "bind.password"

// isLDAPEnabled returns true when the Pooler has LDAP authentication enabled.
func isLDAPEnabled(pooler *apiv1.Pooler) bool {
	return pooler != nil && pooler.Spec.LDAP != nil && pooler.Spec.LDAP.Enabled
}

// isHBAModeWithLDAP returns true when pg_hba rules are defined and LDAP auth is
// active either through spec.ldap or through inline ldap pg_hba rules.
// In this mode auth_type=hba is preserved so PgBouncer routes each connection
// through the HBA file. userlist.txt is also generated for non-LDAP users.
func isHBAModeWithLDAP(pooler *apiv1.Pooler) bool {
	if pooler == nil || pooler.Spec.PgBouncer == nil || len(pooler.Spec.PgBouncer.PgHBA) == 0 {
		return false
	}
	if pooler.Spec.LDAP != nil {
		return pooler.Spec.LDAP.Enabled
	}
	return pgHBAContainsLDAP(pooler.Spec.PgBouncer.PgHBA)
}

func pgHBAContainsLDAP(rules []string) bool {
	for _, rule := range rules {
		if pgHBARuleUsesLDAP(rule) {
			return true
		}
	}
	return false
}

func pgHBARuleUsesLDAP(rule string) bool {
	fields := strings.Fields(rule)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "local":
		return len(fields) > 3 && fields[3] == "ldap"
	case "host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc":
		return len(fields) > 4 && fields[4] == "ldap"
	default:
		return false
	}
}

// encodeLDAPDN percent-encodes a Distinguished Name for use in an LDAP URL path
// (RFC 4516). Characters that are structurally significant in LDAP DNs — comma,
// equals-sign, plus, semicolon — are NOT percent-encoded so PgBouncer can parse
// the DN correctly. url.PathEscape over-encodes these characters.
func encodeLDAPDN(dn string) string {
	encoded := url.PathEscape(dn)
	encoded = strings.ReplaceAll(encoded, "%2C", ",")
	encoded = strings.ReplaceAll(encoded, "%3D", "=")
	encoded = strings.ReplaceAll(encoded, "%2B", "+")
	encoded = strings.ReplaceAll(encoded, "%3B", ";")
	return encoded
}

// buildLDAPURL builds the ldapurl value for auth_ldap_options (RFC 4516).
// Format: ldap://host:port/baseDN??sub?filter or ldaps://host:port/baseDN??sub?filter
// The filter is passed through without percent-encoding because PgBouncer
// performs variable substitution on %u at auth time — encoding % to %25 would
// break username interpolation.
// No sensitive data is included; bind password is supplied via file by the controller.
//
// Scheme selection:
//   - tls.enabled + port == 636 → ldaps:// (implicit TLS, LDAPS)
//   - tls.enabled + port != 636 → ldap:// + ldaptls=1 in auth_ldap_options (StartTLS)
//   - tls disabled              → ldap:// (plain LDAP)
//
// Active Directory typically refuses search operations over plain LDAP, so
// most real deployments use either LDAPS (636) or StartTLS (389).
func buildLDAPURL(pooler *apiv1.Pooler) (string, error) {
	ldap := pooler.Spec.LDAP
	if ldap == nil || !ldap.Enabled {
		return "", nil
	}
	port := apiv1.DefaultLDAPPort
	if ldap.Port != nil {
		port = int(*ldap.Port)
	}
	scheme := "ldap"
	if ldap.TLS != nil && ldap.TLS.Enabled && port == apiv1.DefaultLDAPSPort {
		scheme = "ldaps"
	}
	filter := ldap.SearchFilter
	if filter == "" {
		filter = apiv1.DefaultLDAPSearchFilter
	}
	ldapURL := fmt.Sprintf("%s://%s:%d/%s??sub?%s", scheme, ldap.Host, port, encodeLDAPDN(ldap.BaseDN), filter)
	return ldapURL, nil
}

// GetLDAPBindPasswordFilePath returns the path where the LDAP bind password
// file is read when LDAP is enabled. The Secret is mounted at this path by the
// operator; this package never handles the raw password.
func GetLDAPBindPasswordFilePath() string {
	return LDAPBindPasswordMountDir + "/" + LDAPBindPasswordFileName
}

// buildAuthLDAPOptions returns the value for the auth_ldap_options parameter.
// Only non-sensitive options are included (ldapurl, ldapbinddn, ldapbindpasswdfile path).
// The bind password is stored in a file by the controller; we only reference the path.
func buildAuthLDAPOptions(pooler *apiv1.Pooler) (string, error) {
	ldapURL, err := buildLDAPURL(pooler)
	if err != nil {
		return "", err
	}
	if ldapURL == "" {
		return "", nil
	}
	// PgBouncer: auth_ldap_options = ldapurl="..." ldapbinddn="..." ldapbindpasswdfile="..."
	opts := fmt.Sprintf("ldapurl=\"%s\"", ldapURL)
	if pooler.Spec.LDAP.BindDN != "" {
		opts += fmt.Sprintf(" ldapbinddn=\"%s\"", pooler.Spec.LDAP.BindDN)
	}
	opts += fmt.Sprintf(" ldapbindpasswdfile=\"%s\"", GetLDAPBindPasswordFilePath())

	// StartTLS: when TLS is requested but the URL is plain ldap:// (not 636),
	// tell pgbouncer to upgrade the connection after the initial TCP handshake.
	port := apiv1.DefaultLDAPPort
	if pooler.Spec.LDAP.Port != nil {
		port = int(*pooler.Spec.LDAP.Port)
	}
	if pooler.Spec.LDAP.TLS != nil && pooler.Spec.LDAP.TLS.Enabled && port != apiv1.DefaultLDAPSPort {
		opts += " ldaptls=1"
	}

	if pooler.Spec.LDAP.TLS != nil && pooler.Spec.LDAP.TLS.SkipVerify {
		opts += " ldaptls_noverify=1"
	}
	return opts, nil
}

// applyLDAPParameters injects LDAP-related parameters when LDAP is enabled.
// In pure LDAP mode (no pg_hba rules), auth_type is set to "ldap" globally.
// In HBA mode (pg_hba rules present), auth_type=hba is preserved and only
// auth_ldap_options is injected — the HBA file routes per-user/per-database.
// When LDAP is disabled, parameters are left unchanged (no regression).
func applyLDAPParameters(pooler *apiv1.Pooler, parameters map[string]string) error {
	if !isLDAPEnabled(pooler) {
		return nil
	}
	opts, err := buildAuthLDAPOptions(pooler)
	if err != nil {
		return err
	}
	if !isHBAModeWithLDAP(pooler) {
		parameters["auth_type"] = "ldap"
	}
	parameters["auth_ldap_options"] = opts
	return nil
}
