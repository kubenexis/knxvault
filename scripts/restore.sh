#!/usr/bin/env bash
set -euo pipefail

ADDR="${KNXVAULT_ADDR:-http://localhost:8200}"
TOKEN="${KNXVAULT_TOKEN:?KNXVAULT_TOKEN is required}"
INPUT="${1:?usage: restore.sh <backup-file>}"

curl -sf -X POST "${ADDR}/sys/restore" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary "@${INPUT}"

echo "restore completed from ${INPUT}"