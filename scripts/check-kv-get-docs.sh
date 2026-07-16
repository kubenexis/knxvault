#!/usr/bin/env bash
# Fail when Markdown documents a bare `kv get` without nearby redaction / --show-secrets context.
# Prevents tutorials from implying that default CLI output shows secret plaintext.
#
# A line is a "kv get usage" if it mentions `kv get` (CLI or knxvault-cli).
# It is allowed when:
#   - the same line includes --show-secrets / show-secrets, or
#   - the same line mentions redaction / [REDACTED], or
#   - any line within WINDOW lines before/after does.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINDOW="${KV_GET_DOCS_WINDOW:-3}"
failures=0
checked=0

# shellcheck disable=SC2016
usage_re='(^|[^[:alnum:]_-])(knxvault-cli[[:space:]]+)?kv[[:space:]]+get([^[:alnum:]_-]|$)'

is_allowed_context() {
  local text="$1"
  # Case-insensitive checks for redaction / flag documentation.
  if grep -Eiq -- '--show-secrets|show-secrets|\[REDACTED\]|redact' <<<"$text"; then
    return 0
  fi
  return 1
}

scan_file() {
  local file="$1"
  local -a lines=()
  # Read file into array (preserve empty lines).
  mapfile -t lines <"$file" || true
  local n=${#lines[@]}
  local i line start end window
  for ((i = 0; i < n; i++)); do
    line="${lines[i]}"
    # Skip pure HTML comments / pure link-only noise? Keep simple: only match usage_re.
    if ! grep -Eq -- "$usage_re" <<<"$line"; then
      continue
    fi
    checked=$((checked + 1))
    if is_allowed_context "$line"; then
      continue
    fi
    start=$((i - WINDOW))
    if ((start < 0)); then start=0; fi
    end=$((i + WINDOW))
    if ((end >= n)); then end=$((n - 1)); fi
    window=""
    local j
    for ((j = start; j <= end; j++)); do
      window+="${lines[j]}"$'\n'
    done
    if is_allowed_context "$window"; then
      continue
    fi
    printf 'ERROR: bare kv get without redaction/--show-secrets context\n' >&2
    printf '  file: %s:%d\n' "${file#"$ROOT"/}" "$((i + 1))" >&2
    printf '  line: %s\n' "$line" >&2
    printf '  fix:  add --show-secrets for plaintext examples, or document [REDACTED]/redacted within ±%d lines\n' "$WINDOW" >&2
    failures=$((failures + 1))
  done
}

mapfile -t files < <(
  {
    find "$ROOT/docs" -type f -name '*.md' 2>/dev/null
    [[ -f "$ROOT/README.md" ]] && printf '%s\n' "$ROOT/README.md"
    find "$ROOT/examples" -type f -name '*.md' 2>/dev/null || true
  } | sort -u
)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "no markdown files found under docs/" >&2
  exit 1
fi

for f in "${files[@]}"; do
  scan_file "$f"
done

if ((failures > 0)); then
  printf '\n%d bare kv get documentation issue(s) found (%d kv get lines scanned).\n' "$failures" "$checked" >&2
  exit 1
fi

printf 'docs kv-get lint ok (%d usage lines in %d files, window=±%d)\n' "$checked" "${#files[@]}" "$WINDOW"
