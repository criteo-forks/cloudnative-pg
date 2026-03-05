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
	"regexp"
	"sort"
	"strings"

	apiv1 "github.com/cloudnative-pg/cloudnative-pg/api/v1"
)

// stringifyPgBouncerParameters will take map of PgBouncer parameters and emit
// the relative configuration. We are using a function instead of using the template
// because we want the order of the parameters to be stable to avoid doing rolling
// out new PgBouncer Pods when it's not really needed
func stringifyPgBouncerParameters(parameters map[string]string) (paramsString string) {
	keys := make([]string, 0, len(parameters))
	for k := range parameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		paramsString += fmt.Sprintf("%s = %s\n", k, parameters[k])
	}
	return paramsString
}

// buildPgBouncerParameters will build a PgBouncer configuration applying any
// default parameters and forcing any required parameter needed for the
// controller to work correctly
func buildPgBouncerParameters(userParameters map[string]string) map[string]string {
	params := make(map[string]string, len(userParameters))

	for k, v := range userParameters {
		params[k] = cleanupPgBouncerValue(v)
	}

	for k, defaultValue := range defaultPgBouncerParameters {
		if userValue, ok := params[k]; ok {
			if k == ignoreStartupParametersKey {
				params[k] = strings.Join([]string{defaultValue, userValue}, ",")
			}
			continue
		}
		params[k] = defaultValue
	}

	for k, v := range forcedPgBouncerParameters {
		params[k] = v
	}

	return params
}

// buildLDAPHBAOptions constructs the LDAP option string for a pg_hba.conf rule.
// The output format matches PostgreSQL's HBA LDAP syntax
// (e.g. ldapserver="host" ldapport=389 ldapbasedn="dc=example,dc=com" ...).
func buildLDAPHBAOptions(ldap *apiv1.LDAPConfig, bindPassword string) string {
	var opts string
	opts += fmt.Sprintf("ldapserver=%s", quoteHbaLiteral(ldap.Server))
	if ldap.Port != 0 {
		opts += fmt.Sprintf(" ldapport=%d", ldap.Port)
	}
	if ldap.Scheme != "" {
		opts += fmt.Sprintf(" ldapscheme=%s", quoteHbaLiteral(string(ldap.Scheme)))
	}
	if ldap.TLS {
		opts += " ldaptls=1"
	}
	if ldap.BindAsAuth != nil {
		opts += fmt.Sprintf(" ldapprefix=%s ldapsuffix=%s",
			quoteHbaLiteral(ldap.BindAsAuth.Prefix),
			quoteHbaLiteral(ldap.BindAsAuth.Suffix))
	}
	if ldap.BindSearchAuth != nil {
		opts += fmt.Sprintf(" ldapbasedn=%s ldapbinddn=%s ldapbindpasswd=%s",
			quoteHbaLiteral(ldap.BindSearchAuth.BaseDN),
			quoteHbaLiteral(ldap.BindSearchAuth.BindDN),
			quoteHbaLiteral(bindPassword))
		if ldap.BindSearchAuth.SearchFilter != "" {
			opts += fmt.Sprintf(" ldapsearchfilter=%s",
				quoteHbaLiteral(ldap.BindSearchAuth.SearchFilter))
		}
		if ldap.BindSearchAuth.SearchAttribute != "" {
			opts += fmt.Sprintf(" ldapsearchattribute=%s",
				quoteHbaLiteral(ldap.BindSearchAuth.SearchAttribute))
		}
	}
	return opts
}

// quoteHbaLiteral quotes a string according to pg_hba.conf rules.
// See https://www.postgresql.org/docs/current/auth-pg-hba-conf.html
func quoteHbaLiteral(literal string) string {
	literal = strings.ReplaceAll(literal, `"`, `""`)
	literal = strings.ReplaceAll(literal, "\n", "\\\n")
	return fmt.Sprintf(`"%s"`, literal)
}

// The following regexp will match any newline character. PgBouncer
// doesn't admit newlines inside the configuration at all
var newlineRegexp = regexp.MustCompile(`\r\n|[\r\n\v\f\x{0085}\x{2028}\x{2029}]`)

// cleanupPgBouncerValue removes any newline character from a configuration value.
// The parser used by libusual doesn't support that.
func cleanupPgBouncerValue(parameter string) (escaped string) {
	// See:
	// https://github.com/libusual/libusual/blob/master/usual/cfparser.c  //wokeignore:rule=master
	//
	// The PgBouncer ini file parser doesn't admit any newline character
	// so we are just removing from the value
	return newlineRegexp.ReplaceAllString(parameter, "")
}
