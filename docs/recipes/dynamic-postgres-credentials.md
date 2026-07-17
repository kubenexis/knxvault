<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: Dynamic PostgreSQL credentials

Generate ephemeral database users with automatic lease expiry for PostgreSQL and CloudNativePG (CNPG).

## What you will learn

- Client vs managed execution mode
- Storing admin credentials in KV
- CNPG-specific connection patterns
- Lease renew and revoke

## Prerequisites

- PostgreSQL or CNPG cluster reachable from KNXVault (managed mode) or your executor (client mode)
- Admin DB user with `CREATEROLE` (not necessarily superuser)
- Admin token

## Execution modes

| Mode | KNXVault connects to DB? | You run SQL? |
|------|--------------------------|--------------|
| **client** (default) | No | Yes — using returned `creation_statements` |
| **managed** | Yes — via `pgx` driver | No — automatic |

## Step 1 — Store admin credentials in KV

**Discrete fields (CNPG):**

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

curl -s -X POST "$KNXVAULT_ADDR/secrets/kv/database/admin/cnpg-prod" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "data": {
      "username": "vault_admin",
      "password": "ADMIN_PASSWORD",
      "host": "my-cluster-rw.default.svc",
      "port": "5432",
      "database": "app"
    }
  }'
```

**Or connection URL:**

```bash
curl -s -X POST "$KNXVAULT_ADDR/secrets/kv/database/admin/cnpg-prod" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"connection_url":"postgres://vault_admin:SECRET@my-cluster-rw.default.svc:5432/app?sslmode=require"}}'
```

See `examples/database/cnpg-admin-credentials.json`.

## Step 2 — Configure role (client mode)

```bash
curl -s -X PUT "$KNXVAULT_ADDR/secrets/database/roles/cnpg-readonly" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "ttl_seconds": 3600,
    "username_prefix": "v-",
    "execution_mode": "client",
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

Omit custom SQL to use PostgreSQL defaults for readonly/readwrite privileges.

## Step 3 — Generate credentials (client mode)

```bash
curl -s -X POST "$KNXVAULT_ADDR/secrets/database/creds/cnpg-readonly" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq . > creds.json

jq -r '.creation_statements[]' creds.json
```

Run the statements with admin creds:

```bash
PGPASSWORD=ADMIN_PASSWORD psql -h my-cluster-rw.default.svc -U vault_admin -d app \
  -c "$(jq -r '.creation_statements[0]' creds.json)"
```

Application uses `username` and `password` from the response.

## Step 4 — Managed mode (automatic SQL)

```bash
curl -s -X PUT "$KNXVAULT_ADDR/secrets/database/roles/cnpg-managed" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
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

curl -s -X POST "$KNXVAULT_ADDR/secrets/database/creds/cnpg-managed" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .

# Test login immediately
PGUSER=<username> PGPASSWORD=<password> psql -h my-cluster-rw.default.svc -d app -c 'SELECT 1'
```

## Step 5 — Renew and revoke leases

```bash
LEASE_ID=$(jq -r .lease_id creds.json)

curl -s -X POST "$KNXVAULT_ADDR/secrets/database/renew/$LEASE_ID" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ttl_seconds": 7200}' | jq .

curl -s -X PUT "$KNXVAULT_ADDR/secrets/database/revoke/$LEASE_ID" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN"
```

CLI:

```bash
knxvault-cli database creds cnpg-managed
knxvault-cli database roles get cnpg-managed
```

## CNPG operator notes

- Use `-rw` Service for admin operations; apps can use `-ro` or pooler with ephemeral creds.
- Align `ttl_seconds` with application session lifetime.
- Dedicated `vault_admin` role with `CREATEROLE` — not the `postgres` superuser.

## Verify

```bash
curl -s "$KNXVAULT_ADDR/secrets/database/roles/cnpg-managed" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .

curl -s "$KNXVAULT_ADDR/metrics" | grep knxvault_active_leases
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Managed mode connection refused | NetworkPolicy; wrong `host` in admin KV |
| `CREATEROLE` error | Grant admin role permissions in PostgreSQL |
| Credentials in Raft plaintext | Should not happen — values encrypted per ADR-0004 |

## Related recipes

- [RBAC policies](rbac-policies.md)
- [Orchestrated rotation](orchestrated-rotation.md)
- [KV secrets lifecycle](kv-secrets-lifecycle.md)

## See also

- [Database credentials guide](../deploy/database-credentials.md)
- `examples/database/cnpg-readonly-role.json`