# Dynamic Database Credentials

KNXVault's database secrets engine generates **ephemeral credentials** and **SQL statements**. In the default **client** execution mode, KNXVault does **not** connect to your database or execute SQL.

## Execution model

```
POST /secrets/database/creds/readonly
        │
        ▼
KNXVault returns username, password, lease_id, creation_statements
        │
        ▼
Your job / init container / operator tooling:
  1. Reads admin credentials from external source (see below)
  2. Connects to the database
  3. Runs creation_statements
  4. Hands ephemeral username/password to the application
```

| Field | Purpose |
|-------|---------|
| `execution_mode` | `client` (default) — generator only; `managed` — KNXVault executes SQL |
| `admin_credentials_path` | Optional KV path documenting where **you** store admin DB creds |
| `config` | Non-secret tuning only (`db_type`, `ssl_mode`, `host`) |

**Managed mode** (`execution_mode: managed`) reads admin credentials from `admin_credentials_path` and executes `creation_statements` / `revocation_statements` via `database/sql`. The admin KV secret must include `connection_url` **or** discrete fields (`username`, `password`, `host`, `port`, `database`). SQLite is supported for development; **PostgreSQL and CloudNativePG (CNPG)** are supported in managed mode via the bundled `pgx` driver.

## Configure a role

```bash
# 1. Store admin credentials in KV (encrypted in Raft)
curl -s -X POST $KNXVAULT_ADDR/secrets/kv/database/admin/prod-db \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"username":"vault_admin","password":"admin-pass","host":"db.internal","port":"3306","database":"app"}}'

# 2. Configure the database role (no credentials in config)
curl -s -X PUT $KNXVAULT_ADDR/secrets/database/roles/readonly \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "ttl_seconds": 3600,
    "username_prefix": "v-",
    "execution_mode": "client",
    "admin_credentials_path": "database/admin/prod-db",
    "creation_statements": [
      "CREATE USER '\''{{username}}'\''@'\''%'\'' IDENTIFIED BY '\''{{password}}'\'';"
    ],
    "config": {
      "db_type": "mysql",
      "database_name": "app",
      "ssl_mode": "require"
    }
  }'
```

**Rejected in `config`:** `password`, `connection_url`, `database_url`, `token`, `secret`, and other credential-like keys or embedded URLs.

## Generate credentials

```bash
curl -s -X POST $KNXVAULT_ADDR/secrets/database/creds/readonly \
  -H "Authorization: Bearer $TOKEN"
```

Response includes `creation_statements` with `{{username}}` and `{{password}}` substituted. Run those statements using admin creds from step 1.

## Where admin credentials live

| Source | When to use |
|--------|-------------|
| **KV path** (`database/admin/prod-db`) | Recommended — encrypted before Raft replication |
| **Kubernetes Secret** | Job pod mounts `prod-db-admin` Secret |
| **Cloud IAM** | RDS IAM auth, Cloud SQL connector — no static password |
| **CI variable** | Pipeline holds `DATABASE_ADMIN_URL` outside KNXVault |

In **client** mode, `admin_credentials_path` is a **runbook reference** — your executor fetches that KV secret before running SQL. In **managed** mode, KNXVault reads the path automatically.

## Ephemeral credential storage

Generated username/password pairs are stored under `database/creds/<role>/<lease>` using the same envelope encryption as KV secrets. They are encrypted **before** Raft replication.

## PostgreSQL and CloudNativePG (CNPG)

Set `config.db_type` to `postgres`, `postgresql`, or `cnpg`. When `creation_statements` / `revocation_statements` are omitted, KNXVault applies PostgreSQL defaults for the configured `privilege` (`readonly` or `readwrite`).

| `config` key | Purpose |
|--------------|---------|
| `db_type` | `postgres`, `postgresql`, or `cnpg` |
| `database_name` | Target database for `GRANT CONNECT` |
| `schema` | Schema for table grants (default `public`) |
| `privilege` | `readonly` (default) or `readwrite` |
| `ssl_mode` | Used when building admin `connection_url` from KV fields (default `require`) |

### CNPG admin credentials in KV

Point at the CNPG **primary write service** (`<cluster>-rw.<namespace>.svc`):

```bash
curl -s -X POST $KNXVAULT_ADDR/secrets/kv/database/admin/cnpg-prod \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d @examples/database/cnpg-admin-credentials.json
```

Or store a single `connection_url`:

```json
{"data":{"connection_url":"postgres://vault_admin:SECRET@my-cluster-rw.default.svc:5432/app?sslmode=require"}}
```

### CNPG readonly role (client mode)

```bash
curl -s -X PUT $KNXVAULT_ADDR/secrets/database/roles/cnpg-readonly \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d @examples/database/cnpg-readonly-role.json
```

Generate credentials — response includes rendered `creation_statements` with `{{username}}`, `{{password}}`, `{{expiration}}`, `{{database}}`, and `{{schema}}` substituted:

```bash
curl -s -X POST $KNXVAULT_ADDR/secrets/database/creds/cnpg-readonly \
  -H "Authorization: Bearer $TOKEN"
```

### CNPG managed mode

Use `execution_mode: managed` with the same `db_type: cnpg` config. KNXVault connects with the admin KV secret and executes creation/revocation SQL automatically on generate/revoke.

```bash
curl -s -X PUT $KNXVAULT_ADDR/secrets/database/roles/cnpg-managed \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "ttl_seconds": 3600,
    "username_prefix": "v-",
    "execution_mode": "managed",
    "admin_credentials_path": "database/admin/cnpg-prod",
    "config": {
      "db_type": "cnpg",
      "database_name": "app",
      "schema": "public",
      "privilege": "readonly",
      "ssl_mode": "require"
    }
  }'
```

**CNPG operator notes**

- Use a dedicated `vault_admin` role (not the `postgres` superuser) with `CREATEROLE` and grant admin on the target database.
- Prefer the `-rw` Service for role creation; application workloads can use `-ro` or pooler Services with the ephemeral credentials.
- Ensure `VALID UNTIL` lease expiry aligns with application session lifetime (`ttl_seconds`).

## Related documents

- [ADR-0004: Encrypt before replication](../adr/0004-encrypt-before-replication.md)
- [Security model](../architecture/security-model.md)
- [Getting started](../user/getting-started.md)