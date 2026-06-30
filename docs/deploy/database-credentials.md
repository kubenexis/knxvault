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
| `execution_mode` | `client` (default) — generator only |
| `admin_credentials_path` | Optional KV path documenting where **you** store admin DB creds |
| `config` | Non-secret tuning only (`db_type`, `ssl_mode`, `host`) |

`managed` execution mode (KNXVault connects and runs SQL using KV admin creds) is reserved for a future release.

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

`admin_credentials_path` is a **runbook reference** in client mode. KNXVault does not read it automatically today; your executor should fetch that KV secret (or use external creds) before running SQL.

## Ephemeral credential storage

Generated username/password pairs are stored under `database/creds/<role>/<lease>` using the same envelope encryption as KV secrets. They are encrypted **before** Raft replication.

## Related documents

- [ADR-0004: Encrypt before replication](../adr/0004-encrypt-before-replication.md)
- [Security model](../architecture/security-model.md)
- [Getting started](../user/getting-started.md)