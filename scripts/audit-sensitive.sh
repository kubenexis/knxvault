#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail=0

check_path_uses_sensitive() {
  local file="$1"
  local label="$2"
  if grep -qE 'sensitive\.(New|Buffer)|OpenSensitive' "$file" 2>/dev/null; then
    echo "ok: $label uses sensitive buffer"
  elif grep -q 'memzero\.Bytes' "$file" 2>/dev/null; then
    echo "ok: $label uses memzero"
  else
    echo "warn: $label should use sensitive.Buffer or memzero" >&2
    fail=1
  fi
}

check_path_uses_sensitive internal/api/handlers/sys.go "unseal handler"
check_path_uses_sensitive internal/crypto/service.go "crypto service (memzero via sensitive on Open paths)"

if command -v gosec >/dev/null 2>&1; then
  gosec -quiet -include=G401,G501 ./internal/auth/... ./internal/backup/... 2>/dev/null || true
fi

exit "$fail"