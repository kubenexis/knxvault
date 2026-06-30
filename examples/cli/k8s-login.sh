#!/usr/bin/env bash
set -euo pipefail

: "${KNXVAULT_ADDR:=http://localhost:8200}"
: "${KNXVAULT_K8S_ROLE:=admin}"
: "${KNXVAULT_SA_JWT:?set KNXVAULT_SA_JWT to a Kubernetes service account token}"

curl -fsS -X POST "${KNXVAULT_ADDR}/auth/kubernetes" \
  -H "Content-Type: application/json" \
  -d "{\"role\":\"${KNXVAULT_K8S_ROLE}\",\"jwt\":\"${KNXVAULT_SA_JWT}\"}"
echo