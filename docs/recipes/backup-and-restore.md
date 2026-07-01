# Recipe: Backup and restore

Create encrypted portable backups and restore full vault state for disaster recovery or migration.

## What you will learn

- Backup archive format and encryption
- `include_audit` option
- Restore via `snapshot.import` on Raft clusters
- Pre-restore validation

## Prerequisites

- Admin token
- `KNXVAULT_MASTER_KEY` documented in your secrets manager
- For restore: target cluster with **matching** master key

## Concepts

| Component | Detail |
|-----------|--------|
| **Export** | Linearizable `snapshot.export` on Raft leader — consistent graph |
| **Archive** | JSON with `format: knxvault-backup`, encrypted payload |
| **Contents** | CAs, secrets, RBAC, leases, revocations, issued cert metadata; optional audit |
| **Restore** | `snapshot.import` replaces entire state machine (not merge) |

```
POST /sys/backup  →  atomic export  →  Seal(master key)  →  file
POST /sys/restore →  Open(master key) → ValidateSnapshot → snapshot.import
```

## Create a backup

**CLI (recommended):**

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

knxvault-cli backup create -o knxvault-backup.json
```

**API with audit history:**

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/backup" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"include_audit":true}' \
  | jq -r '.data' | base64 -d > knxvault-backup-with-audit.json
```

**Cron wrapper:**

```bash
./scripts/backup.sh /var/backups/knxvault/$(date +%Y%m%d).json
```

## Verify backup file

```bash
jq -r '.format' knxvault-backup.json
# knxvault-backup

ls -lh knxvault-backup.json
# Non-empty; ciphertext present — not plaintext secrets
```

Store backups off-cluster (object storage, encrypted volume). Restrict access to the same level as `KNXVAULT_MASTER_KEY`.

## Restore to a cluster

> **Warning:** Restore **replaces** all vault state. Use a maintenance window or a fresh staging namespace.

### 1. Confirm master key matches

```bash
# Target cluster must use the same KNXVAULT_MASTER_KEY as when backup was created
kubectl -n knxvault get secret knxvault -o jsonpath='{.data.KNXVAULT_MASTER_KEY}' | base64 -d
```

### 2. Restore

**CLI:**

```bash
knxvault-cli backup restore -f knxvault-backup.json
```

**API:**

```bash
curl -sf -X POST "$KNXVAULT_ADDR/sys/restore" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @knxvault-backup.json
```

### 3. Verify restored state

```bash
knxvault-cli doctor
knxvault-cli kv get <path-from-backup> --show-secrets

curl -s -X POST "$KNXVAULT_ADDR/audit/verify" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$(curl -s $KNXVAULT_ADDR/audit/export -H "Authorization: Bearer $KNXVAULT_TOKEN")" | jq .
```

## Disaster recovery workflow

1. Provision fresh 3-node cluster (same K8s manifests).
2. Set **original** `KNXVAULT_MASTER_KEY` and root token in `secret.yaml`.
3. Wait for pods Ready.
4. `backup restore` from latest off-site archive.
5. Verify KV, PKI, policies; re-enable audit forwarding.
6. Run [Raft failover recovery](raft-failover-recovery.md) smoke tests.

## When to take backups

| Event | Action |
|-------|--------|
| Before [master key rotation](master-key-rotation.md) | Mandatory |
| Before [rolling upgrade](rolling-upgrade-ha.md) | Mandatory |
| Before `restore` on production | Snapshot current state first |
| Daily cron | `scripts/backup.sh` to object storage |

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Decrypt error on restore | Wrong `KNXVAULT_MASTER_KEY` |
| Validation failed | Corrupt archive; broken audit chain; try older backup |
| Partial data after restore | Restore is atomic — if it succeeded, state matches snapshot time |

## Related recipes

- [Master key rotation](master-key-rotation.md)
- [Deploy 3-node cluster](deploy-3-node-cluster.md)
- [Audit export](audit-export.md)

## See also

- [Backup & restore guide](../deploy/backup-restore.md)
- [Raft HA & recovery](../storage/raft-ha-and-recovery.md)