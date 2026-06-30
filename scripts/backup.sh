#!/usr/bin/env bash
set -euo pipefail

ADDR="${KNXVAULT_ADDR:-http://localhost:8200}"
TOKEN="${KNXVAULT_TOKEN:?KNXVAULT_TOKEN is required}"
OUTPUT="${1:-knxvault-backup-$(date +%F).json}"

curl -sf -X POST "${ADDR}/sys/backup" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  | jq -r '.data' | base64 -d > "${OUTPUT}"

echo "backup written to ${OUTPUT}"