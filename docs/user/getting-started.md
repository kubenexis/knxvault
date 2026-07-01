# Getting Started

A hands-on introduction to KNXVault secrets, PKI, and access control.

## Prerequisites

A running KNXVault instance. See [Installation guide](../installation/install.md).

```bash
export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=dev-root-token   # bootstrap token
```

## Core concepts

| Concept | Description |
|---------|-------------|
| **Secrets engine** | Pluggable backend for secret types (KVv2, database creds, PKI) |
| **Path** | Hierarchical identifier (e.g. `app/database/password`) |
| **Policy** | RBAC document granting capabilities on path prefixes |
| **Token** | Opaque credential presented as `Authorization: Bearer` |
| **Lease** | Time-bounded dynamic credential with renew/revoke |
| **CA hierarchy** | Root → intermediate → leaf certificate chain |

## 1. Authenticate

```bash
curl -s -X POST $KNXVAULT_ADDR/auth/token \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$KNXVAULT_TOKEN\"}"
```

Kubernetes workloads use `POST /auth/kubernetes` with a ServiceAccount JWT. In-cluster **TokenReview** is used automatically in production. `KNXVAULT_JWT_SECRET` is for local dev only.

## 2. Store and read a secret

**CLI:**

```bash
./bin/knxvault-cli kv put app/db password=s3cret host=db.internal
./bin/knxvault-cli kv get app/db
```

**API:**

```bash
# Write
curl -s -X POST $KNXVAULT_ADDR/secrets/kv/app/db \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"password":"s3cret"},"options":{"ttl":"24h"}}'

# Read latest version
curl -s $KNXVAULT_ADDR/secrets/kv/app/db \
  -H "Authorization: Bearer $KNXVAULT_TOKEN"
```

KVv2 supports versioning, TTL expiration, and check-and-set via the `options` block.

## 3. Create a PKI hierarchy

```bash
# Root CA (self-signed trust anchor)
curl -s -X POST $KNXVAULT_ADDR/pki/root \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"dev-root","common_name":"KNXVault Root CA","ttl":"8760h"}'

# Issue a leaf certificate — role is the CA name
curl -s -X POST $KNXVAULT_ADDR/pki/issue \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "role": "dev-root",
    "common_name": "api.example.com",
    "dns_names": ["api.example.com"],
    "ttl": "720h",
    "auto_renew": true
  }'
```

Set `"auto_renew": true` to track the certificate for background renewal by the Raft leader.

Detailed recipes (intermediate CA, trust bundles, Kubernetes): [PKI administration](../operations/pki-administration.md).

## 4. Define access control

```bash
# Policy: read-only access to app secrets
curl -s -X PUT $KNXVAULT_ADDR/sys/policies/app-reader \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "paths": {
      "secrets/kv/app/*": {"capabilities": ["read"]},
      "inject/render": {"capabilities": ["read"]}
    }
  }'

# Role binding
curl -s -X PUT $KNXVAULT_ADDR/sys/roles/app-sa \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "policies": ["app-reader"],
    "bound_service_account_names": ["my-app"],
    "bound_service_account_namespaces": ["production"]
  }'
```

Check effective capabilities:

```bash
curl -s $KNXVAULT_ADDR/sys/capabilities \
  -H "Authorization: Bearer $KNXVAULT_TOKEN"
```

## 5. Dynamic database credentials

KNXVault generates credentials and SQL statements; **your tooling runs the SQL** using admin credentials stored outside the role (typically in KV). See [Database credentials guide](../deploy/database-credentials.md).

```bash
# Store admin DB credentials in KV (encrypted before Raft)
curl -s -X POST $KNXVAULT_ADDR/secrets/kv/database/admin/prod-db \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"username":"vault_admin","password":"admin-pass","host":"db.internal"}}'

# Configure role (no credentials in config)
curl -s -X PUT $KNXVAULT_ADDR/secrets/database/roles/readonly \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "ttl_seconds": 3600,
    "username_prefix": "v-",
    "admin_credentials_path": "database/admin/prod-db",
    "creation_statements": ["CREATE USER '\''{{username}}'\''@'\''%'\'' IDENTIFIED BY '\''{{password}}'\'';"],
    "config": {"db_type": "mysql"}
  }'

# Generate ephemeral credentials + SQL statements
curl -s -X POST $KNXVAULT_ADDR/secrets/database/creds/readonly \
  -H "Authorization: Bearer $KNXVAULT_TOKEN"
```

Renew with `POST /secrets/database/renew/:lease_id`; revoke with `PUT /secrets/database/revoke/:lease_id`.

## 6. Inject secrets into pods

Use `POST /inject/render` from an init container or sidecar. See [Secrets injection](../deploy/secrets-injection.md).

## Next steps

- [Recipes index](../recipes/README.md) — step-by-step guides for production tasks
- [CLI reference](../cli/reference.md)
- [API reference](../api/reference.md)
- [Integration overview](../integration/overview.md)
- [PKI administration](../operations/pki-administration.md)
- [Day-2 operations](../operations/day2.md)