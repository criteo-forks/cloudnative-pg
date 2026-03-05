-- init-grants.sql
-- One-time SQL to set up permissions for the LDAP group roles.
-- Run as superuser against the pgrdsdb database after the managed roles are created.
--
-- Usage:
--   kubectl exec pg-instance-<primary> -n pgrdsdb -c postgres -- \
--     psql -U postgres -d pgrdsdb -f /dev/stdin < init-grants.sql

-- =============================================================================
-- Full access role: g-app-postgresql-pgrdsdb-f
-- =============================================================================

GRANT CONNECT ON DATABASE pgrdsdb TO "g-app-postgresql-pgrdsdb-f";
GRANT USAGE ON SCHEMA public TO "g-app-postgresql-pgrdsdb-f";

GRANT SELECT, INSERT, UPDATE, DELETE
  ON ALL TABLES IN SCHEMA public
  TO "g-app-postgresql-pgrdsdb-f";

GRANT USAGE, SELECT
  ON ALL SEQUENCES IN SCHEMA public
  TO "g-app-postgresql-pgrdsdb-f";

GRANT EXECUTE
  ON ALL FUNCTIONS IN SCHEMA public
  TO "g-app-postgresql-pgrdsdb-f";

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "g-app-postgresql-pgrdsdb-f";

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO "g-app-postgresql-pgrdsdb-f";

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO "g-app-postgresql-pgrdsdb-f";


-- =============================================================================
-- Read-only role: g-app-postgresql-pgrdsdb-ro
-- =============================================================================

GRANT CONNECT ON DATABASE pgrdsdb TO "g-app-postgresql-pgrdsdb-ro";
GRANT USAGE ON SCHEMA public TO "g-app-postgresql-pgrdsdb-ro";

GRANT SELECT
  ON ALL TABLES IN SCHEMA public
  TO "g-app-postgresql-pgrdsdb-ro";

GRANT USAGE, SELECT
  ON ALL SEQUENCES IN SCHEMA public
  TO "g-app-postgresql-pgrdsdb-ro";

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT ON TABLES TO "g-app-postgresql-pgrdsdb-ro";

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO "g-app-postgresql-pgrdsdb-ro";
