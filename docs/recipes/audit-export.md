<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: Audit export

Export the tamper-evident audit log and verify hash chain integrity for compliance reviews.

## What you will learn

- Audit entry schema and hash chaining
- `GET /audit/export` with filters
- `POST /audit/verify` for integrity checks
- Optional signed export heads

## Prerequisites

- Admin or audit-reader token
- `KNXVAULT_AUDIT_SIGNING_KEY` set for signed export heads (recommended in production)

## Concepts

Each API action appends an `audit.Entry` to a **hash chain**:

```
entry[n].hash = H(entry[n-1].hash || entry[n].payload)
```

Export returns entries plus `head_hash`. Optional HMAC `signature` over the head enables offline verification.

| Field | Description |
|-------|-------------|
| `actor` | Token subject or auth principal |
| `action` | e.g. `secret.read`, `auth.login` |
| `resource` | API path or logical resource |
| `status` | `success` / `failure` |
| `hash` | Chain link for this entry |

## Step 1 — Generate auditable events

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

knxvault-cli kv put audit/demo value=test
knxvault-cli kv get audit/demo --show-secrets
curl -s -X PUT "$KNXVAULT_ADDR/sys/policies/audit-test" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"paths":{"secrets/kv/audit/*":{"capabilities":["read"]}}}'
```

## Step 2 — Export full bundle

```bash
curl -s "$KNXVAULT_ADDR/audit/export" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  | jq . > audit-export.json

jq '{entries: (.entries|length), head_hash, signature, signed_at}' audit-export.json
```

## Step 3 — Export with filters

```bash
# Pagination
curl -s "$KNXVAULT_ADDR/audit/export?limit=100&offset=0" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .

# Since timestamp (RFC3339)
curl -s "$KNXVAULT_ADDR/audit/export?since=2026-07-01T00:00:00Z" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq '.entries | length'
```

## Step 4 — Verify integrity

```bash
curl -s -X POST "$KNXVAULT_ADDR/audit/verify" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @audit-export.json | jq .
```

Expected: `valid: true` (or equivalent success field).

## Step 5 — Tamper detection demo

```bash
jq '(.entries[0].hash)="tampered"' audit-export.json > audit-tampered.json

curl -s -X POST "$KNXVAULT_ADDR/audit/verify" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @audit-tampered.json | jq .
# Expected: verification failure
```

## Step 6 — Compliance archive workflow

```bash
# Daily cron
DATE=$(date +%Y%m%d)
curl -s "$KNXVAULT_ADDR/audit/export?since=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  | jq . > "/archives/knxvault-audit-$DATE.json"

curl -s -X POST "$KNXVAULT_ADDR/audit/verify" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @"/archives/knxvault-audit-$DATE.json" | jq -r '.valid // .status'
```

Store archives in WORM storage or object-lock buckets.

## Include audit in backups

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/backup" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"include_audit":true}' | jq -r '.data' | base64 -d > backup-with-audit.json
```

See [Backup and restore](backup-and-restore.md).

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Empty export | No auditable events yet; check seal state |
| Verify fails on fresh export | Clock skew on `signed_at`; re-export |
| No `signature` field | Set `KNXVAULT_AUDIT_SIGNING_KEY` in deployment |

## Related recipes

- [Audit SIEM forwarding](audit-siem-forwarding.md)
- [RBAC policies](rbac-policies.md)

## See also

- [Audit forwarding](../observability/audit-forwarding.md)
- [Operator security](../operations/operator-security.md)