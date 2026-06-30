#!/usr/bin/env bash
set -euo pipefail

: "${KNXVAULT_ADDR:=http://localhost:8200}"
: "${KNXVAULT_TOKEN:?set KNXVAULT_TOKEN}"
: "${BACKUP_FILE:=knxvault-backup.enc}"

echo "Creating encrypted backup at ${BACKUP_FILE}"
curl -fsS -X POST "${KNXVAULT_ADDR}/sys/backup" \
  -H "Authorization: Bearer ${KNXVAULT_TOKEN}" \
  -o "${BACKUP_FILE}"
echo "Backup written to ${BACKUP_FILE}"