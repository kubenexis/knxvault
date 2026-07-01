#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [[ "${KNXVAULT_SMOKE:-}" != "1" ]]; then
  echo "Skipping live SDK smoke tests (set KNXVAULT_SMOKE=1 to run against a server)."
  go test ./tests/clients/... -count=1
  exit 0
fi

export KNXVAULT_ADDR="${KNXVAULT_ADDR:-http://localhost:8200}"
export KNXVAULT_TOKEN="${KNXVAULT_TOKEN:-}"

go test ./tests/clients/... -count=1 -tags=smoke