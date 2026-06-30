# Backup & Restore

KNXVault exports an encrypted JSON archive containing CAs, secrets, RBAC configuration, leases, issued certificate metadata, and revocations.

## API

```bash
# Create backup (admin token required)
curl -s -X POST http://localhost:8200/sys/backup \
  -H "Authorization: Bearer ${KNXVAULT_ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"include_audit":false}' \
  | jq -r '.data' | base64 -d > knxvault-backup.json

# Restore (replaces PostgreSQL state when configured)
curl -sf -X POST http://localhost:8200/sys/restore \
  -H "Authorization: Bearer ${KNXVAULT_ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @knxvault-backup.json
```

## CLI

```bash
export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=dev-root-token

./bin/knxvault-cli backup create -o knxvault-backup.json
./bin/knxvault-cli backup restore -f knxvault-backup.json
```

## Shell scripts

[`scripts/backup.sh`](../../scripts/backup.sh) and [`scripts/restore.sh`](../../scripts/restore.sh) wrap the HTTP API for cron jobs and pre-upgrade hooks.

## Requirements

- `KNXVAULT_MASTER_KEY` must match the key used when the backup was created.
- PostgreSQL restores truncate vault tables before import. Run against a maintenance window.
- In-memory mode supports export; restore targets a fresh process or empty repositories.

## Archive format

The on-disk file is JSON with `format: knxvault-backup`, master-key-encrypted payload (`ciphertext`, `dek_enc`), and snapshot version `1`.