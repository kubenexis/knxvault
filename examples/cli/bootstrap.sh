#!/usr/bin/env bash
set -euo pipefail

: "${KNXVAULT_ADDR:=http://localhost:8200}"
: "${KNXVAULT_TOKEN:?set KNXVAULT_TOKEN}"

echo "Initializing KNXVault at ${KNXVAULT_ADDR}"
curl -fsS -X POST "${KNXVAULT_ADDR}/sys/init" \
  -H "Authorization: Bearer ${KNXVAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"create_root_ca":true,"root_ca_name":"root","root_common_name":"KNXVault Root CA"}'
echo