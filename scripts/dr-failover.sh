#!/usr/bin/env bash
# W35-01: DR failover drill — restore latest backup on standby cluster.
set -euo pipefail
ADDR="${KNXVAULT_ADDR:-http://localhost:8200}"
TOKEN="${KNXVAULT_TOKEN:?set KNXVAULT_TOKEN}"
BACKUP="${1:?usage: dr-failover.sh backup.tar.enc}"

echo "==> uploading backup to $ADDR"
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  -F "archive=@${BACKUP}" \
  "${ADDR}/sys/restore"

echo "==> checking readiness"
curl -fsS "${ADDR}/ready" | jq .
echo "DR restore complete"