<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: KV secrets lifecycle

Store, update, version, retrieve, list, and delete secrets using the KVv2 secrets engine.

## What you will learn

- How KV versioning works
- Reading specific versions vs latest
- Check-and-set (CAS) writes
- Soft delete vs permanent destroy

## Prerequisites

- Running KNXVault with a valid admin token
- `curl`, `jq`, and/or `knxvault-cli`

```bash
export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=<admin-token>
```

## Concepts

| Concept | Behavior |
|---------|----------|
| **Path** | Logical name, e.g. `app/database/config` (stored under `secrets/kv/`) |
| **Version** | Each `POST` creates a new version; old versions remain readable |
| **Latest** | Default read returns the highest non-deleted version |
| **Encryption** | Payload encrypted with envelope AES-256-GCM **before** Raft replication |
| **Metadata** | Paths and version numbers are cleartext in Raft (by design — see ADR-0005) |

## Store a secret (version 1)

**CLI:**

```bash
knxvault-cli kv put app/db password=s3cret host=db.internal port=5432
```

**API:**

```bash
curl -s -X POST "$KNXVAULT_ADDR/secrets/kv/app/db" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "data": {
      "password": "s3cret",
      "host": "db.internal",
      "port": "5432"
    }
  }' | jq .
```

Response includes `version: 1`.

## Update a secret (version 2)

Each write increments the version:

```bash
curl -s -X POST "$KNXVAULT_ADDR/secrets/kv/app/db" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"password":"rotated-secret","host":"db.internal","port":"5432"}}' | jq .
```

## Retrieve secrets

**Latest version:**

```bash
knxvault-cli kv get app/db --show-secrets

curl -s "$KNXVAULT_ADDR/secrets/kv/app/db" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .
```

**Specific version:**

```bash
curl -s "$KNXVAULT_ADDR/secrets/kv/app/db?version=1" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .
```

## List versions and metadata

```bash
# All versions for a path
curl -s "$KNXVAULT_ADDR/secrets/kv/app/db/versions" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .

# Metadata (current version, created time, etc.)
curl -s "$KNXVAULT_ADDR/secrets/kv/app/db/metadata" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .
```

## List paths under a prefix

```bash
curl -s "$KNXVAULT_ADDR/secrets/kv/app?list=true" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .
```

## Check-and-set (CAS)

Prevent lost updates by requiring the expected current version:

```bash
curl -s -X POST "$KNXVAULT_ADDR/secrets/kv/app/db" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "data": {"password": "cas-safe"},
    "options": {"cas_version": 2}
  }' | jq .
```

Wrong `cas_version` → request rejected.

## Delete and destroy

**Soft delete** (marks latest version deleted; older versions may remain):

```bash
curl -s -X DELETE "$KNXVAULT_ADDR/secrets/kv/app/db" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" -w "\nHTTP %{http_code}\n"
```

**Destroy a specific version** (permanent):

```bash
curl -s -X DELETE "$KNXVAULT_ADDR/secrets/kv/app/db?version=1" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" -w "\nHTTP %{http_code}\n"
```

## TTL options

Set expiration on write:

```bash
curl -s -X POST "$KNXVAULT_ADDR/secrets/kv/app/session" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"token":"short-lived"},"options":{"ttl":"1h"}}' | jq .
```

## Verify

```bash
# v1 still readable after v2 created
curl -s "$KNXVAULT_ADDR/secrets/kv/app/db?version=1" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq -r '.data.data.password'
# → s3cret

# Latest returns v2
curl -s "$KNXVAULT_ADDR/secrets/kv/app/db" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq -r '.data.data.password'
# → rotated-secret
```

Audit entries are recorded for reads and writes when audit is enabled.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `403 Forbidden` | Token lacks `secrets/kv` read/write — check [RBAC policies](rbac-policies.md) |
| `404` on read | Path typo or all versions deleted |
| CAS rejected | Re-read metadata for current version number |

## Related recipes

- [Secret rotation](secret-rotation.md)
- [RBAC policies](rbac-policies.md)
- [CSI driver integration](csi-driver-integration.md)
- [Backup and restore](backup-and-restore.md)

## See also

- [Envelope encryption](../architecture/envelope-encryption.md)
- [API reference — KV](../api/reference.md)