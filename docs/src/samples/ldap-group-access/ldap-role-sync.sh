#!/usr/bin/env bash
set -euo pipefail

# ldap-role-sync.sh
# Syncs LDAP group membership to PostgreSQL role membership.
# Runs as a Kubernetes CronJob.

# ---------------------------------------------------------------------------
# Configuration (injected via environment variables)
# ---------------------------------------------------------------------------
: "${LDAP_URI:?LDAP_URI is required}"
: "${LDAP_BIND_DN:?LDAP_BIND_DN is required}"
: "${LDAP_BIND_PASSWORD:?LDAP_BIND_PASSWORD is required}"
: "${LDAP_BASE_DN:?LDAP_BASE_DN is required}"

: "${LDAP_GROUP_FULL:?LDAP_GROUP_FULL DN is required}"
: "${LDAP_GROUP_RO:?LDAP_GROUP_RO DN is required}"
: "${PG_GROUP_FULL:=g-app-postgresql-pgrdsdb-f}"
: "${PG_GROUP_RO:=g-app-postgresql-pgrdsdb-ro}"

: "${PGHOST:?PGHOST is required}"
: "${PGPORT:=5432}"
: "${PGDATABASE:=pgrdsdb}"
: "${PGUSER:=postgres}"
: "${PGPASSWORD:?PGPASSWORD is required}"

export PGHOST PGPORT PGDATABASE PGUSER PGPASSWORD
export LDAPTLS_REQCERT="${LDAPTLS_REQCERT:-never}"

LOG_PREFIX="[ldap-role-sync]"

log() { echo "${LOG_PREFIX} $(date -Iseconds) $*"; }

# ---------------------------------------------------------------------------
# Fetch LDAP group members (returns list of sAMAccountName, one per line)
# ---------------------------------------------------------------------------
get_group_members() {
  local group_dn="$1"
  ldapsearch -LLL -H "${LDAP_URI}" \
    -D "${LDAP_BIND_DN}" \
    -w "${LDAP_BIND_PASSWORD}" \
    -b "${LDAP_BASE_DN}" \
    "(&(objectClass=user)(objectCategory=person)(memberOf=${group_dn}))" \
    sAMAccountName 2>/dev/null \
  | grep -i '^sAMAccountName:' \
  | awk '{print tolower($2)}' \
  | sort -u
}

# ---------------------------------------------------------------------------
# Get current PostgreSQL role members for a group role
# ---------------------------------------------------------------------------
get_pg_members() {
  local pg_group="$1"
  psql -t -A -c "
    SELECT m.rolname
    FROM pg_auth_members am
    JOIN pg_roles r ON r.oid = am.roleid
    JOIN pg_roles m ON m.oid = am.member
    WHERE r.rolname = '${pg_group}'
    ORDER BY m.rolname;
  " 2>/dev/null | tr '[:upper:]' '[:lower:]' | sort -u
}

# ---------------------------------------------------------------------------
# Sync one LDAP group → one PostgreSQL group role
# ---------------------------------------------------------------------------
sync_group() {
  local ldap_group_dn="$1"
  local pg_group="$2"
  local group_label="$3"

  log "Syncing ${group_label}: LDAP group=${ldap_group_dn} → PG role=${pg_group}"

  local ldap_members pg_members
  ldap_members=$(get_group_members "${ldap_group_dn}")
  pg_members=$(get_pg_members "${pg_group}")

  if [ -z "${ldap_members}" ]; then
    log "  WARNING: No members found in LDAP group ${group_label}. Skipping to avoid accidental mass revoke."
    return
  fi

  local members_to_add members_to_remove
  members_to_add=$(comm -23 <(echo "${ldap_members}") <(echo "${pg_members}"))
  members_to_remove=$(comm -13 <(echo "${ldap_members}") <(echo "${pg_members}"))

  # Grant membership to new LDAP group members
  if [ -n "${members_to_add}" ]; then
    while IFS= read -r user; do
      [ -z "${user}" ] && continue
      log "  ADD: ${user} → ${pg_group}"
      psql -c "
        DO \$\$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${user}') THEN
            EXECUTE format('CREATE ROLE %I LOGIN INHERIT', '${user}');
          END IF;
          EXECUTE format('GRANT %I TO %I', '${pg_group}', '${user}');
        END
        \$\$;
      " 2>&1 | sed "s/^/  /"
    done <<< "${members_to_add}"
  fi

  # Revoke membership from users no longer in the LDAP group
  if [ -n "${members_to_remove}" ]; then
    while IFS= read -r user; do
      [ -z "${user}" ] && continue
      # Skip reserved CNPG roles
      case "${user}" in
        postgres|cnpg_pooler_pgbouncer|streaming_replica) continue ;;
      esac
      log "  REMOVE: ${user} ← ${pg_group}"
      psql -c "REVOKE \"${pg_group}\" FROM \"${user}\";" 2>&1 | sed "s/^/  /"
    done <<< "${members_to_remove}"
  fi

  local count
  count=$(echo "${ldap_members}" | wc -l)
  log "  Done. ${count} member(s) in LDAP group ${group_label}."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
log "Starting LDAP → PostgreSQL role sync"

sync_group "${LDAP_GROUP_FULL}" "${PG_GROUP_FULL}" "full-access"
sync_group "${LDAP_GROUP_RO}"   "${PG_GROUP_RO}"   "read-only"

log "Sync completed successfully"
