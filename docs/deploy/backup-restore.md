<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Backup & Restore

KNXVault exports an encrypted JSON archive containing CAs, secrets, RBAC configuration, client token hashes, leases, issued certificate metadata, and revocations. Optional audit history is included when `include_audit` is true.

## API

```bash
# Create backup (admin token required)
curl -s -X POST http://localhost:8200/sys/backup \
  -H "Authorization: Bearer ${KNXVAULT_ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"include_audit":false}' \
  | jq -r '.data' | base64 -d > knxvault-backup.json

# Restore (replaces Raft state via snapshot.import)
curl -sf -X POST http://localhost:8200/sys/restore \
  -H "Authorization: Bearer ${KNXVAULT_ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @knxvault-backup.json
```

## CLI

```bash
export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=dev-root-token

./build/bin/knxvault-cli backup create -o knxvault-backup.json
./build/bin/knxvault-cli backup restore -f knxvault-backup.json
```

## Shell scripts

[`scripts/backup.sh`](../../scripts/backup.sh) and [`scripts/restore.sh`](../../scripts/restore.sh) wrap the HTTP API for cron jobs and pre-upgrade hooks.

## Requirements

- `KNXVAULT_MASTER_KEY` must match the key used when the backup was created.
- Raft restores propose `snapshot.import` — run against a maintenance window or a fresh cluster.
- In-memory mode supports export; restore **replaces** existing repository state (not merge).
- Snapshots are validated before import (CA/PKI references, RBAC policy refs, issued-cert CA refs, audit hash chain when hashes are present).
- After restore, the in-memory RBAC cache is reloaded from persisted policies.

## Raft-specific notes

When `KNXVAULT_RAFT_ENABLED=true`, backup also triggers an on-disk Dragonboat snapshot. Restore replaces the full state machine contents. See [Dragonboat storage](../storage/dragonboat.md), [Raft HA & recovery](../storage/raft-ha-and-recovery.md), and [Raft failover runbook](../operations/runbooks/raft-failover.md).

## Archive format

The on-disk file is JSON with `format: knxvault-backup`, master-key-encrypted payload (`ciphertext`, `dek_enc`), and snapshot version `1`.