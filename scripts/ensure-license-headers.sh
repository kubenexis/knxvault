#!/usr/bin/env bash
# Copyright Kubenexis Systems Private Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Ensure SPDX license headers on source and documentation (CNCF Charter §11).
# Usage:
#   scripts/ensure-license-headers.sh          # apply missing headers
#   scripts/ensure-license-headers.sh --check  # exit 1 if any missing
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

COPYRIGHT="Copyright Kubenexis Systems Private Limited."
missing=0
updated=0

has_spdx() {
  head -n 50 "$1" | grep -q 'SPDX-License-Identifier'
}

should_skip() {
  local f="$1"
  case "$f" in
    ./build/*|./.git/*|./LICENSES/*|./vendor/*|*/vendor/*) return 0 ;;
    *coverage*|*.out|*.sbom.json) return 0 ;;
  esac
  [[ ! -s "$f" ]] && return 0
  return 1
}

# Insert header after optional shebang / go build tags / YAML --- marker.
# Args: file, license (Apache-2.0|CC-BY-4.0), style (go|hash|md)
insert_header() {
  local f="$1" license="$2" style="$3"
  python3 - "$f" "$license" "$style" "$COPYRIGHT" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
license_id = sys.argv[2]
style = sys.argv[3]
copyright_line = sys.argv[4]
text = path.read_text(encoding="utf-8")
lines = text.splitlines(keepends=True)
if not lines:
    sys.exit(0)

if style == "go":
    hdr = f"// {copyright_line}\n// SPDX-License-Identifier: {license_id}\n\n"
elif style == "md":
    hdr = f"<!--\n{copyright_line}\nSPDX-License-Identifier: {license_id}\n-->\n\n"
else:  # hash comments
    hdr = f"# {copyright_line}\n# SPDX-License-Identifier: {license_id}\n\n"

i = 0
# shebang
if lines[0].startswith("#!"):
    i = 1
    if i < len(lines) and lines[i].strip() == "":
        i += 1

# go build constraints
if style == "go":
    while i < len(lines) and (
        lines[i].startswith("//go:build")
        or lines[i].startswith("// +build")
    ):
        i += 1
    if i < len(lines) and lines[i].strip() == "":
        i += 1

# YAML document start
if style == "hash" and i < len(lines) and lines[i].strip() == "---":
    i += 1

new_text = "".join(lines[:i]) + hdr + "".join(lines[i:])
path.write_text(new_text, encoding="utf-8")
PY
}

process() {
  local f="$1" license="$2" style="$3"
  if should_skip "$f"; then
    return 0
  fi
  if has_spdx "$f"; then
    return 0
  fi
  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "missing SPDX header: $f"
    missing=$((missing + 1))
    return 0
  fi
  insert_header "$f" "$license" "$style"
  updated=$((updated + 1))
  echo "added SPDX header: $f"
}

# --- Code (Apache-2.0) ---
while IFS= read -r -d '' f; do
  process "$f" "Apache-2.0" go
done < <(find ./cmd ./internal ./pkg ./scripts ./test ./api -type f -name '*.go' -print0 2>/dev/null)

while IFS= read -r -d '' f; do
  process "$f" "Apache-2.0" hash
done < <(find ./scripts -type f \( -name '*.sh' -o -name '*.bash' \) -print0 2>/dev/null)

# Note: .gosec.json is pure JSON (no comments) — license via REUSE.toml only.
for f in ./Makefile ./Dockerfile ./Dockerfile.operator ./.golangci.yml ./.dockerignore ./.gitignore ./.trivyignore ./REUSE.toml; do
  [[ -f "$f" ]] && process "$f" "Apache-2.0" hash
done

# YAML/YML/TOML only — pure JSON cannot carry # SPDX comments; covered by REUSE.toml.
while IFS= read -r -d '' f; do
  process "$f" "Apache-2.0" hash
done < <(find ./deployments ./config ./examples ./api -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.toml' \) -print0 2>/dev/null)

# --- Documentation (CC-BY-4.0) ---
while IFS= read -r -d '' f; do
  case "$f" in
    ./docs/LICENSE) continue ;;
  esac
  process "$f" "CC-BY-4.0" md
done < <(find ./docs -type f -name '*.md' -print0 2>/dev/null)

for f in ./README.md ./NOTICE; do
  [[ -f "$f" ]] || continue
  if [[ "$f" == "./NOTICE" ]]; then
    process "$f" "Apache-2.0" hash
  else
    process "$f" "CC-BY-4.0" md
  fi
done

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  if [[ "$missing" -gt 0 ]]; then
    echo "error: $missing file(s) missing SPDX-License-Identifier headers" >&2
    echo "Run: bash scripts/ensure-license-headers.sh" >&2
    exit 1
  fi
  echo "SPDX header check passed"
  exit 0
fi

echo "SPDX headers: updated $updated file(s)"
