# LDAP Authentication via PgBouncer in CloudNativePG

## Overview

This document describes the changes made to CloudNativePG (CNPG) to support LDAP
authentication through PgBouncer, how the authentication flow works, and the full
configuration required to deploy it.

LDAP authentication support was introduced in PgBouncer 1.25.0. This integration
leverages the **"LDAP via HBA"** strategy: PgBouncer uses `auth_type = hba` and
delegates authentication decisions to an HBA file that contains `ldap` rules.

---

## 1. Changes Made to CloudNativePG

### 1.1 Architecture of Changes

```
cloudnative-pg/
├── api/v1/
│   ├── pooler_types.go              ← New LDAPConfig field in PgBouncerSpec
│   └── zz_generated.deepcopy.go    ← DeepCopy methods for new types
│
├── pkg/management/pgbouncer/config/
│   ├── config.go                    ← Conditional auth_type + auth_query logic
│   ├── strings.go                   ← buildLDAPHBAOptions() helper
│   └── data.go                      ← LDAPBindPassword added to Secrets struct
│
├── internal/
│   ├── controller/
│   │   ├── pooler_resources.go      ← LDAPBindPasswordSecret in managed resources
│   │   ├── pooler_status.go         ← Secret version tracking
│   │   └── pooler_controller.go     ← Watch/reconcile on LDAP secret changes
│   │
│   ├── pgbouncer/management/controller/
│   │   └── secrets.go               ← Fetch LDAP bind password secret
│   │
│   └── webhook/v1/
│       └── pooler_webhook.go        ← validatePgBouncerLDAP() validation
│
└── pkg/specs/pgbouncer/
    └── rbac.go                      ← LDAP secret added to RBAC Role
```

### 1.2 API Changes (`pooler_types.go`)

A new `LDAP` field was added to `PgBouncerSpec`, reusing the existing `LDAPConfig`
type from `cluster_types.go` (which already supports the full PostgreSQL HBA LDAP
syntax):

```go
// PgBouncerSpec defines the desired state of PgBouncer
type PgBouncerSpec struct {
    // ... existing fields ...

    // LDAP configures LDAP authentication for PgBouncer via pg_hba rules.
    // Requires PgBouncer >= 1.25.0.
    // +optional
    LDAP *LDAPConfig `json:"ldap,omitempty"`
}

// LDAPBindPassword was added to PgBouncerSecrets
type PgBouncerSecrets struct {
    // ... existing fields ...
    LDAPBindPassword *SecretVersion `json:"ldapBindPassword,omitempty"`
}
```

**LDAPConfig** supports two authentication modes:

| Mode | Description |
|------|-------------|
| `bindAsAuth` | Simple bind: PgBouncer constructs the full DN from `prefix + username + suffix` and binds directly |
| `bindSearchAuth` | Search+bind: PgBouncer first binds with a service account, searches for the user DN, then binds again with the user's credentials |

### 1.3 HBA File Generation (`config.go` + `strings.go`)

When `spec.pgbouncer.ldap` is set with a valid auth mode, the operator generates
a `pg_hba.conf` for PgBouncer containing `ldap` rules:

**Before (no LDAP):**
```ini
[pgbouncer]
auth_type = md5
auth_query = SELECT usename, passwd FROM public.user_search($1)
```

**After (with LDAP):**
```ini
[pgbouncer]
auth_type = hba
auth_hba_file = /controller/configs/pg_hba.conf
# auth_query is omitted — incompatible with LDAP
```

Generated `pg_hba.conf`:
```
local pgbouncer pgbouncer peer

host all all 0.0.0.0/0 ldap \
  ldapserver="ldap.example.com" \
  ldapport=636 \
  ldapscheme="ldaps" \
  ldapbasedn="OU=Users,DC=example,DC=com" \
  ldapbinddn="CN=svc-account,OU=Services,DC=example,DC=com" \
  ldapbindpasswd="secret" \
  ldapsearchattribute="sAMAccountName"

host all all ::/0 ldap [same options]
```

> **Note:** `auth_query` is explicitly removed when LDAP is active, because PgBouncer
> does not support both LDAP and database-based authentication simultaneously.

### 1.4 Secret Reconciliation (`pooler_controller.go`, `secrets.go`)

The operator watches the LDAP bind password Secret and triggers a Pooler
reconciliation whenever it changes:

```
Secret (ldap bind password) ──watch──► Pooler reconcile ──► regenerate pg_hba.conf
```

### 1.5 Webhook Validation (`pooler_webhook.go`)

A new validation function `validatePgBouncerLDAP` enforces:

- If `spec.pgbouncer.ldap` is set, at least one of `bindAsAuth` or `bindSearchAuth`
  must be configured (a bare `ldap: {server: ...}` without an auth mode is rejected).
- If `bindSearchAuth` is set, `bindPassword.name` must be non-empty.

### 1.6 RBAC (`rbac.go`)

The operator automatically grants the PgBouncer ServiceAccount read access to the
LDAP bind password Secret by adding it to the generated `Role`:

```yaml
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames:
      - pg-instance-pooler
      - pg-instance-ca
      - pg-instance-server
      - <ldap-bind-password-secret-name>   # ← added automatically
    verbs: ["get", "watch"]
```

---

## 2. How LDAP Authentication Works

### 2.1 Full Authentication Flow

```
┌─────────────┐         ┌─────────────────────────────────────────────────────────┐         ┌──────────────┐
│             │         │                     PgBouncer Pod                        │         │              │
│   Client    │         │ ┌──────────────────────────────────────────────────────┐ │         │  PostgreSQL   │
│             │         │ │                  pg_hba.conf                          │ │         │   Cluster    │
│  user:      │──(1)───►│ │  host all all 0.0.0.0/0 ldap ldapserver=...          │ │         │              │
│  b.riquier  │         │ └─────────────────┬────────────────────────────────────┘ │         │              │
│  password:  │         │                   │ LDAP rule matched                     │         │              │
│  xxxxxxxx   │         │         ┌─────────▼──────────┐                           │         │              │
│             │         │         │   LDAP Auth Worker  │                           │         │              │
└─────────────┘         │         │   (separate thread) │                           │         │              │
                        │         └──────────┬──────────┘                           │         │              │
                        │                    │                                       │         │              │
                        └────────────────────┼───────────────────────────────────────┘         │              │
                                             │                                                   │              │
                        ┌────────────────────┼───────────────────────────────────────────────────┼──────────────┐
                        │                    │              LDAP / AD Server                      │              │
                        │         ┌──────────▼──────────┐                                        │              │
                        │         │  (2) Service bind    │                                        │              │
                        │         │  DN: CN=svc-account  │                                        │              │
                        │         │  pwd: from Secret    │◄── TLS (LDAPS port 636)                │              │
                        │         └──────────┬──────────┘                                        │              │
                        │                    │ bind OK                                             │              │
                        │         ┌──────────▼──────────┐                                        │              │
                        │         │  (3) Search user     │                                        │              │
                        │         │  filter:             │                                        │              │
                        │         │  (sAMAccountName=    │                                        │              │
                        │         │   b.riquier)         │                                        │              │
                        │         └──────────┬──────────┘                                        │              │
                        │                    │ DN found: CN=b.riquier,OU=...                      │              │
                        │         ┌──────────▼──────────┐                                        │              │
                        │         │  (4) User bind       │                                        │              │
                        │         │  DN: CN=b.riquier    │                                        │              │
                        │         │  pwd: client's pwd   │                                        │              │
                        │         └──────────┬──────────┘                                        │              │
                        └────────────────────┼───────────────────────────────────────────────────┼──────────────┘
                                             │ bind OK → identity confirmed                       │
                                             │                                                    │
                        ┌────────────────────┼───────────────────────────────────────┐           │
                        │  PgBouncer         │                                        │           │
                        │         ┌──────────▼──────────┐                           │           │
                        │         │  (5) Open backend    │──(TLS mutual auth)───────►│           │
                        │         │  connection as user  │   server_tls_sslmode=     │           │
                        │         │  "b.riquier"         │   verify-ca               │           │
                        │         └──────────┬──────────┘                           │           │
                        └────────────────────┼───────────────────────────────────────┘           │
                                             │                                                    │
                                             │ (6) pg_hba on PostgreSQL side:                    │
                                             │     hostssl all all ... trust                     │
                                             │       clientcert=verify-ca                        │
                                             │     → verify client cert, accept (role must exist)│
                                             ▼                                                    │
                                    Session established                                           │
```

### 2.2 Step-by-Step Description

| Step | Actor | Action |
|------|-------|--------|
| **(1)** Client connects | Client | Sends `user`, `password`, `database` to PgBouncer |
| **(2)** Service account bind | PgBouncer → LDAP | Binds with `ldapbinddn` / `ldapbindpasswd`. The bind password comes from the Kubernetes Secret `<serviceaccountname>-default-secrets` (same service account as the Pooler). Fails → "Invalid credentials" |
| **(3)** User search | PgBouncer → LDAP | Searches `ldapbasedn` with filter `(sAMAccountName=<username>)`. Returns user's full DN |
| **(4)** User bind | PgBouncer → LDAP | Binds with the user's full DN + the password provided by the client. Fails → "LDAP authentication failed" |
| **(5)** Backend connection | PgBouncer → PostgreSQL | Opens (or reuses) a TLS-authenticated connection to PostgreSQL **as the authenticated user**, presenting its client certificate signed by the CNPG CA |
| **(6)** PostgreSQL access | PostgreSQL | Applies `pg_hba.conf`: `hostssl ... trust clientcert=verify-ca`. Verifies the client certificate against `ssl_ca_file` (CNPG CA). If valid → accepts. If missing or invalid → rejects with `FATAL: connection requires a valid client certificate`. The role must exist in PostgreSQL |

### 2.3 What Each Component Decides

```
┌─────────────────────────────────────────────────────┐
│  "Is this username + password valid?"                │
│                                      → LDAP / AD    │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  "Is this user allowed to have a database session?"  │
│  "What can they do?"                                 │
│                                      → PostgreSQL    │
│                                        (role exists  │
│                                         + GRANTs)    │
└─────────────────────────────────────────────────────┘
```

### 2.4 TLS in Detail

```
Client ──[TLS: prefer]──► PgBouncer ──[TLS: verify-ca + client cert]──► PostgreSQL
                              │                                          (clientcert=verify-ca)
                              │
                              └──[LDAPS: port 636, TLS_REQCERT demand]──► LDAP Server
                                                    (CA verified)
```

- **Client → PgBouncer**: `client_tls_sslmode = prefer` (TLS offered but not enforced).
  For production, consider using `require` or `verify-ca` to prevent cleartext credentials.
- **PgBouncer → PostgreSQL**: `server_tls_sslmode = verify-ca` with a client certificate
  signed by the CNPG cluster CA. PostgreSQL enforces `clientcert=verify-ca` in its
  `pg_hba.conf`, rejecting any connection that does not present a certificate signed
  by the cluster CA. This ensures only legitimate Pooler instances can connect.
- **PgBouncer → LDAP**: LDAPS (TLS on port 636). The `ldap.conf` file should set
  `TLS_REQCERT demand` with `TLS_CACERT` pointing to the LDAP server's CA certificate,
  so that PgBouncer verifies the LDAP server identity and prevents MITM attacks.

---

## 3. Required Configuration

### 3.1 Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Kubernetes Namespace                                                        │
│                                                                              │
│  ┌──────────────────────┐    ┌──────────────────────┐                       │
│  │  Secret              │    │  ConfigMap            │                       │
│  │  <bind-pwd-secret>   │    │  ldap-conf            │                       │
│  │  key: password       │    │  ldap.conf:           │                       │
│  │  val: <svc-password> │    │    TLS_REQCERT never  │                       │
│  └──────────┬───────────┘    └──────────┬────────────┘                       │
│             │                           │                                    │
│             ▼                           ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Pooler                                                               │   │
│  │  spec.pgbouncer.ldap:                                                 │   │
│  │    server, scheme, port, bindSearchAuth (→ Secret ref)                │   │
│  │  spec.template.spec:                                                  │   │
│  │    env: LDAPTLS_REQCERT=never                                         │   │
│  │    volumeMount: ldap-conf → /etc/ldap/ldap.conf                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Cluster (PostgreSQL)                                                 │   │
│  │  spec.postgresql.pg_hba:                                              │   │
│  │    hostssl all all 10.0.0.0/8 trust clientcert=verify-ca ← Pooler    │   │
│  │    host    all all 0.0.0.0/0  md5     ← Direct connections           │   │
│  │  spec.managed.roles:                                                  │   │
│  │    - name: b.riquier  (login: true, no password needed)               │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Secret — LDAP Bind Password

Contains the password for the LDAP service account used to perform the initial bind
and user search in the directory. **This is the same service account as the one used
by the Pooler itself** (i.e. the Pooler's Kubernetes ServiceAccount and the LDAP
bind DN share the same identity).

The password is stored in a Kubernetes Secret following the naming convention
`<serviceaccountname>-default-secrets`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pgrdsdb-default-secrets   # Convention: <serviceaccountname>-default-secrets
  namespace: pgrdsdb
type: Opaque
stringData:
  password: "YourServiceAccountPassword"
```

The Pooler references this secret in its LDAP configuration:

```yaml
bindPassword:
  name: pgrdsdb-default-secrets   # Must match the Secret name above
  key: password
```

> Store the actual password in a secrets manager (Vault, Sealed Secrets, etc.).
> Never commit it in plain text.

### 3.3 ConfigMap — OpenLDAP Client Configuration

Required on **Debian-based** PgBouncer images (CNPG default) to configure
the `libldap` TLS behaviour. The file must be mounted at `/etc/ldap/ldap.conf`.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ldap-conf
  namespace: pgrdsdb
data:
  ldap.conf: |
    TLS_REQCERT demand
    TLS_CACERT /etc/ssl/certs/ldap-ca/ca.crt
```

> **Why is this necessary?**  
> PgBouncer uses the system OpenLDAP library (`libldap.so.2`). On Debian images,
> this library reads `/etc/ldap/ldap.conf` at startup for TLS settings.
> `TLS_REQCERT demand` tells libldap to verify the LDAP server's certificate
> against the CA specified by `TLS_CACERT`, preventing MITM attacks.

> **⚠️ `TLS_REQCERT never` should be avoided in production.**  
> While `never` may simplify initial setup with internal AD servers using a
> private CA, it disables all server certificate verification. An attacker
> performing a MITM on the LDAP connection could intercept user passwords
> during bind operations. Always mount the LDAP CA certificate and use `demand`.

The LDAP CA certificate must be mounted from a Secret:

```yaml
volumes:
  - name: ldap-ca
    secret:
      secretName: ldap-ca
```

### 3.4 Pooler Resource

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Pooler
metadata:
  name: pgrdsdb
  namespace: pgrdsdb
spec:
  cluster:
    name: pg-instance
  instances: 2

  pgbouncer:
    poolMode: session
    parameters:
      default_pool_size: "40"
      max_client_conn: "200"

    ldap:
      # LDAP server hostname
      server: "ldaps.example.com"
      # Use LDAPS (TLS on connect)
      scheme: ldaps
      # Explicit port (default would be 389; required for LDAPS)
      port: 636
      # Search+bind mode: service account searches for the user, then binds as them
      bindSearchAuth:
        baseDN: "OU=Users,DC=example,DC=com"
        bindDN: "CN=svc-pgbouncer,OU=Services,DC=example,DC=com"
        bindPassword:
          name: pgrdsdb-default-secrets   # <serviceaccountname>-default-secrets
          key: password
        searchAttribute: "sAMAccountName"  # AD attribute matching the PostgreSQL username

  template:
    spec:
      # hostNetwork may be required in some environments for DNS resolution
      # of internal LDAP server names via Consul/internal resolvers
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet

      containers:
        - name: pgbouncer
          env:
            - name: LDAPTLS_REQCERT
              value: "demand"
          volumeMounts:
            - name: ldap-conf
              mountPath: /etc/ldap/ldap.conf
              subPath: ldap.conf
              readOnly: true
            - name: ldap-ca
              mountPath: /etc/ssl/certs/ldap-ca
              readOnly: true

      volumes:
        - name: ldap-conf
          configMap:
            name: ldap-conf
        - name: ldap-ca
          secret:
            secretName: ldap-ca
```

#### Pooler — `bindAsAuth` alternative (simple bind)

Use this mode when the LDAP DN can be constructed directly from the username:

```yaml
ldap:
  server: "ldap.example.com"
  port: 389
  bindAsAuth:
    prefix: "CN="
    suffix: ",OU=Users,DC=example,DC=com"
    # Result: CN=b.riquier,OU=Users,DC=example,DC=com
```

No service account or bind password secret is needed in this mode.

### 3.5 PostgreSQL Cluster

#### pg_hba Rules

```yaml
spec:
  postgresql:
    pg_hba:
      # Pooler connects over TLS with a client certificate signed by the CNPG CA.
      # clientcert=verify-ca ensures PostgreSQL rejects any connection that does
      # not present a valid certificate signed by its trusted CA (ssl_ca_file).
      # Only PgBouncer pods have this certificate — other pods in the cluster do not.
      - hostssl all all 10.0.0.0/8 trust clientcert=verify-ca

      # Direct connections (e.g. admin tools, migrations) still require a password.
      - host all all 0.0.0.0/0 md5
```

> **Why `trust` with `clientcert=verify-ca`?**  
> LDAP authentication is performed by PgBouncer before the PostgreSQL connection
> is opened. By the time a connection reaches PostgreSQL, the user has already been
> authenticated by LDAP. The `clientcert=verify-ca` option ensures that PostgreSQL
> only accepts connections from clients presenting a certificate signed by the
> CNPG cluster CA (`ssl_ca_file`). Since only PgBouncer pods hold this certificate,
> arbitrary pods in the cluster **cannot** connect directly to PostgreSQL.
>
> **⚠️ Without `clientcert=verify-ca`, plain `trust` accepts any SSL connection
> from the given CIDR without any identity check.** This means any pod in the
> Kubernetes cluster with an IP in `10.0.0.0/8` could bypass PgBouncer entirely
> and access PostgreSQL as any role (including superuser) without a password.
> Always use `clientcert=verify-ca` when combining `trust` with LDAP-based pooling.

> **`verify-ca` vs `verify-full`**: `verify-ca` checks that the client certificate
> is signed by the trusted CA, but does not match the certificate CN against the
> PostgreSQL username. This is required here because PgBouncer uses a single
> certificate to connect as multiple different users. `verify-full` would require
> `CN = username`, which would fail.

#### Creating PostgreSQL Roles for LDAP Users

LDAP handles password verification. PostgreSQL only needs to know the role exists:

```sql
-- Create a role for each LDAP user. No password is needed (LDAP provides auth).
CREATE ROLE "b.riquier" LOGIN;
CREATE ROLE "another.user" LOGIN;

-- Grant appropriate privileges
GRANT CONNECT ON DATABASE pgrdsdb TO "b.riquier";
GRANT USAGE ON SCHEMA public TO "b.riquier";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "b.riquier";
```

Alternatively, manage roles declaratively in the Cluster spec:

```yaml
spec:
  managed:
    roles:
      - name: b.riquier
        login: true
        inherit: true
        connectionLimit: -1
        ensure: present
        # No passwordSecret needed — authentication is via LDAP
```

### 3.6 Summary Table

| Resource | Purpose | Key Fields |
|----------|---------|------------|
| **Secret** `<sa>-default-secrets` | Holds the LDAP service account password (same SA as the Pooler). Naming convention: `<serviceaccountname>-default-secrets` | `data.password` |
| **ConfigMap** `ldap-conf` | Configures `libldap` TLS behaviour on the Debian-based PgBouncer image | `data.ldap.conf` with `TLS_REQCERT` |
| **Pooler** | Declares LDAP config; operator generates `pg_hba.conf` and mounts the bind password | `spec.pgbouncer.ldap`, `spec.template` |
| **Cluster** `pg_hba` | Allows Pooler connections with client certificate verification | `hostssl ... trust clientcert=verify-ca` for Pooler CIDR |
| **Cluster** roles | Authorises LDAP-authenticated users to have a database session | `spec.managed.roles` or SQL `CREATE ROLE` |

---

## 4. Security Considerations

### 4.1 Defense in Depth

```
[Client]
   │
   │  TLS (prefer → recommend require)
   ▼
[PgBouncer]  ← LDAP verifies identity (password)
   │              LDAP server cert verified (TLS_REQCERT demand)
   │
   │  Mutual TLS (verify-ca + client cert signed by CNPG CA)
   ▼
[PostgreSQL] ← clientcert=verify-ca rejects connections without valid cert
               Role and GRANT controls authorisation
```

Three independent security layers protect the database:

1. **LDAP** validates the user's password (identity).
2. **Client certificate (`clientcert=verify-ca`)** ensures only PgBouncer (holding
   a cert signed by the CNPG CA) can open backend connections to PostgreSQL.
   Other pods in the cluster do not have this certificate and are rejected.
3. **PostgreSQL roles and GRANTs** control what the authenticated user can do.

### 4.2 Critical: `clientcert=verify-ca` on PostgreSQL pg_hba

The `pg_hba.conf` rule for PgBouncer connections **must** include `clientcert=verify-ca`:

```
hostssl all all 10.0.0.0/8 trust clientcert=verify-ca
```

**Without `clientcert=verify-ca`**, the `trust` method accepts any SSL connection
from the CIDR without verifying client identity. This means:

- Any pod in the Kubernetes cluster with an IP in `10.0.0.0/8` can connect directly
  to PostgreSQL, bypassing PgBouncer and LDAP authentication entirely.
- An attacker can connect as **any role**, including `postgres` (superuser), without
  a password: `psql "sslmode=require host=<pg-service> user=postgres"`.

**With `clientcert=verify-ca`**, PostgreSQL requires the client to present a TLS
certificate signed by the cluster CA (`ssl_ca_file`). Only PgBouncer pods have
this certificate (provisioned by the CNPG operator). All other clients receive:

```
FATAL: connection requires a valid client certificate
```

**`verify-ca` vs `verify-full`**: Use `verify-ca` (not `verify-full`) because
PgBouncer uses a single certificate to connect as multiple PostgreSQL users.
`verify-full` would require the certificate CN to match the username, which would
fail since the cert CN is the cluster name, not individual usernames.

### 4.3 LDAP TLS Verification

PgBouncer connects to the LDAP server to verify user passwords. If this connection
is not properly secured, an attacker performing a MITM can:

- Intercept all user passwords during LDAP bind operations.
- Return forged "bind OK" responses to authorize any user.

**Required configuration:**

1. Set `LDAPTLS_REQCERT=demand` (env var on the PgBouncer container).
2. Mount the LDAP CA certificate from a Secret.
3. Configure `/etc/ldap/ldap.conf` with `TLS_REQCERT demand` and `TLS_CACERT`
   pointing to the mounted CA file.

**`TLS_REQCERT never` should only be used for initial testing**, never in production.

### 4.4 LDAP Bind Password Exposure

The LDAP service account password (`ldapbindpasswd`) appears in plaintext in the
generated `pg_hba.conf` inside the PgBouncer pod. This is a limitation of the
PgBouncer HBA syntax. Mitigations:

- Restrict `kubectl exec` access to PgBouncer pods via Kubernetes RBAC.
- Rotate the LDAP bind password regularly.
- Store the source password in a secrets manager (Vault, Sealed Secrets).
- The file permissions are `0600` (owner-only), reducing exposure within the pod.

### 4.5 Recommendations Summary

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Direct PostgreSQL access bypassing PgBouncer | **Critical** | `clientcert=verify-ca` on pg_hba (blocks unauthenticated access) + NetworkPolicy |
| LDAP MITM (password interception) | **High** | `TLS_REQCERT demand` + mount LDAP CA certificate |
| LDAP bind password visible in pg_hba.conf | **Medium** | Restrict `kubectl exec` via RBAC; rotate password regularly |
| `trust` on a broad CIDR (`/8`) | **Medium** | Narrow the CIDR to the actual Pooler/pod network; `clientcert=verify-ca` already mitigates |
| Client connections in cleartext | **Low** | Use `client_tls_sslmode = require` instead of `prefer` |
| `hostNetwork: true` on PgBouncer | **Low** | Required for DNS resolution in some environments; mitigate with host-level firewall rules |
| PgBouncer pod privilege escalation | **Mitigated** | `runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities: drop ALL`, `seccompProfile: RuntimeDefault` |

### 4.6 Recommended NetworkPolicy

Deploy a NetworkPolicy as defense in depth. Note that if PgBouncer uses
`hostNetwork: true`, the effectiveness depends on the CNI implementation
(some CNIs do not enforce policies on host-network traffic).

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: pg-instance-ingress
  namespace: pgrdsdb
spec:
  podSelector:
    matchLabels:
      cnpg.io/cluster: pg-instance
  policyTypes: ["Ingress"]
  ingress:
    # PgBouncer → PostgreSQL
    - from:
        - podSelector:
            matchLabels:
              cnpg.io/poolerName: pgrdsdb
      ports:
        - port: 5432
    # PostgreSQL replication (instance to instance)
    - from:
        - podSelector:
            matchLabels:
              cnpg.io/cluster: pg-instance
      ports:
        - port: 5432
    # Monitoring (Prometheus → exporter)
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: prometheus
      ports:
        - port: 9187
```

---

## 5. LDAP Group-Based Access Control

LDAP groups can be used to control which users can connect and what permissions
they receive. This combines:

1. **PgBouncer `searchFilter`** to restrict authentication to group members only.
2. **PostgreSQL group roles** to manage permissions (full access vs read-only).
3. **A CronJob** to sync LDAP group membership to PostgreSQL role membership.

### 5.1 Architecture

```
                    ┌──────────────────────────────────────┐
                    │          Active Directory             │
                    │                                      │
                    │  g-app-postgresql-pgrdsdb-f           │
                    │    └─ user-a, user-b (full access)   │
                    │                                      │
                    │  g-app-postgresql-pgrdsdb-ro          │
                    │    └─ user-c, user-d (read-only)     │
                    └──────────┬──────────┬────────────────┘
                               │          │
              ┌────────────────┘          └───────────────────┐
              ▼                                                ▼
  ┌─────────────────────┐                         ┌─────────────────────┐
  │  PgBouncer           │                         │  CronJob             │
  │  searchFilter:       │                         │  ldap-role-sync      │
  │  memberOf check      │                         │  (every 5 min)       │
  │  → deny if not in    │                         │  ldapsearch → psql   │
  │    either group      │                         │  CREATE ROLE + GRANT │
  └──────────┬───────────┘                         └──────────┬───────────┘
             │                                                 │
             ▼                                                 ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  PostgreSQL                                                          │
  │                                                                      │
  │  ROLE "g-app-postgresql-pgrdsdb-f"  (NOLOGIN, full access GRANTs)   │
  │    ├─ ROLE "user-a" (LOGIN, INHERIT)                                │
  │    └─ ROLE "user-b" (LOGIN, INHERIT)                                │
  │                                                                      │
  │  ROLE "g-app-postgresql-pgrdsdb-ro" (NOLOGIN, read-only GRANTs)     │
  │    ├─ ROLE "user-c" (LOGIN, INHERIT)                                │
  │    └─ ROLE "user-d" (LOGIN, INHERIT)                                │
  └──────────────────────────────────────────────────────────────────────┘
```

### 5.2 PgBouncer — Restrict Authentication to Group Members

Use `searchFilter` in the Pooler spec to add an LDAP group membership check
during authentication. Users not in either group are denied access by PgBouncer
before reaching PostgreSQL.

```yaml
spec:
  pgbouncer:
    ldap:
      bindSearchAuth:
        baseDN: "OU=Fimusers,DC=uadpreprod,DC=preprod,DC=crto,DC=in"
        bindDN: "CN=svc-pgrdsdb,OU=FimServices,DC=uadpreprod,DC=preprod,DC=crto,DC=in"
        bindPassword:
          name: pgrdsdb-default-secrets
          key: password
        searchFilter: >-
          (&(sAMAccountName=$username)
            (|(memberOf=CN=g-app-postgresql-pgrdsdb-f,OU=FimGroups,DC=uadpreprod,DC=preprod,DC=crto,DC=in)
              (memberOf=CN=g-app-postgresql-pgrdsdb-ro,OU=FimGroups,DC=uadpreprod,DC=preprod,DC=crto,DC=in)))
        searchAttribute: "sAMAccountName"
```

The `$username` placeholder is replaced by PgBouncer with the connecting user's
name. If the LDAP search returns no result (user is not in either group), PgBouncer
returns "LDAP authentication failed for user".

> **Nested groups**: If your AD groups use nested membership, replace `memberOf`
> with `memberOf:1.2.840.113556.1.4.1941:` to enable recursive group resolution.

### 5.3 PostgreSQL Group Roles

Create two group roles (NOLOGIN) via CNPG managed roles:

```yaml
spec:
  managed:
    roles:
      - name: g-app-postgresql-pgrdsdb-f
        login: false
        inherit: true
        ensure: present
        comment: "Full access to pgrdsdb — synced from LDAP group"
      - name: g-app-postgresql-pgrdsdb-ro
        login: false
        inherit: true
        ensure: present
        comment: "Read-only access to pgrdsdb — synced from LDAP group"
```

Then apply GRANTs (one-time, as superuser on the `pgrdsdb` database):

```sql
-- Full access
GRANT CONNECT ON DATABASE pgrdsdb TO "g-app-postgresql-pgrdsdb-f";
GRANT USAGE ON SCHEMA public TO "g-app-postgresql-pgrdsdb-f";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
  TO "g-app-postgresql-pgrdsdb-f";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "g-app-postgresql-pgrdsdb-f";

-- Read-only
GRANT CONNECT ON DATABASE pgrdsdb TO "g-app-postgresql-pgrdsdb-ro";
GRANT USAGE ON SCHEMA public TO "g-app-postgresql-pgrdsdb-ro";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "g-app-postgresql-pgrdsdb-ro";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT ON TABLES TO "g-app-postgresql-pgrdsdb-ro";
```

### 5.4 CronJob — LDAP to PostgreSQL Role Sync

A Kubernetes CronJob runs every 5 minutes to synchronize LDAP group membership
to PostgreSQL roles. For each LDAP group member, it:

1. Queries AD with `ldapsearch` for `sAMAccountName` of all group members.
2. Creates missing PostgreSQL roles (`CREATE ROLE ... LOGIN INHERIT`).
3. Grants group role membership (`GRANT "g-app-..." TO "username"`).
4. Revokes membership from users no longer in the LDAP group.

The CronJob uses:
- Secret `pgrdsdb-default-secrets` for LDAP bind password.
- Secret `pg-instance-superuser` for PostgreSQL superuser access.

See the full manifests in [samples/ldap-group-access/](samples/ldap-group-access/).

### 5.5 Deployment Steps

1. **Apply the Cluster patch** to declare group roles:
   ```bash
   kubectl patch cluster pg-instance -n pgrdsdb --type merge \
     --patch-file cluster-roles-patch.yaml
   ```

2. **Run the init SQL** to set up GRANTs (once, after roles are created):
   ```bash
   kubectl exec pg-instance-2 -n pgrdsdb -c postgres -- \
     psql -U postgres -d pgrdsdb -f /dev/stdin < init-grants.sql
   ```

3. **Apply the Pooler patch** to enable group-based authentication:
   ```bash
   kubectl patch pooler pgrdsdb -n pgrdsdb --type merge \
     --patch-file pooler-patch.yaml
   ```

4. **Deploy the CronJob**:
   ```bash
   kubectl create configmap ldap-role-sync-script \
     --from-file=ldap-role-sync.sh -n pgrdsdb
   kubectl apply -f cronjob.yaml
   ```

5. **Verify** by triggering a manual run:
   ```bash
   kubectl create job ldap-role-sync-manual \
     --from=cronjob/ldap-role-sync -n pgrdsdb
   kubectl logs -f job/ldap-role-sync-manual -n pgrdsdb
   ```

---

## 6. Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Can't contact LDAP server` | `LDAPTLS_CACERT` points to a non-existent file, or `libldap` rejects the server certificate | Remove `LDAPTLS_CACERT` if the file does not exist; ensure `/etc/ldap/ldap.conf` has `TLS_REQCERT never` |
| `LDAP can't be used together with database authentication` | `auth_query` is set while LDAP is active | Fixed in operator: `auth_query` is now omitted when LDAP is configured |
| `Invalid credentials` | Wrong bind password, expired account, or locked account | Verify the Secret content; check AD account status |
| `role "x" does not exist` | User authenticated by LDAP but no PostgreSQL role exists | Create the role: `CREATE ROLE "x" LOGIN;` |
| `strict decoding error: unknown field "spec.pgbouncer.ldap"` | CRD on the cluster is outdated | Apply the updated CRD: `kubectl apply --server-side --force-conflicts -f config/crd/bases/postgresql.cnpg.io_poolers.yaml` |
| LDAP auth fails for a valid group member | `searchFilter` syntax error, wrong group DN, or the user is in a nested group not resolved by default `memberOf` | Verify the filter with `ldapsearch` directly; for nested groups use `memberOf:1.2.840.113556.1.4.1941:=CN=...` |
| User authenticates but gets `permission denied` | User role exists but is not a member of the PostgreSQL group role | Check CronJob logs; verify with `SELECT r.rolname, m.rolname FROM pg_auth_members am JOIN pg_roles r ON r.oid=am.roleid JOIN pg_roles m ON m.oid=am.member;` |
| CronJob finds 0 members (WARNING in logs) | Wrong LDAP group DN, bind password expired, or LDAP connectivity issue | Run `ldapsearch` manually with the same parameters to debug |
