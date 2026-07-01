#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${ROOT}/api/openapi.yaml"
STAMP="${ROOT}/clients/.openapi-sha256"

if [[ ! -f "${SPEC}" ]]; then
  echo "missing OpenAPI spec: ${SPEC}" >&2
  exit 1
fi

current="$(sha256sum "${SPEC}" | awk '{print $1}')"
if [[ ! -f "${STAMP}" ]]; then
  echo "${current}" > "${STAMP}"
  echo "initialized clients/.openapi-sha256"
  exit 0
fi

expected="$(tr -d '[:space:]' < "${STAMP}")"
if [[ "${current}" != "${expected}" ]]; then
  echo "OpenAPI spec changed; regenerate clients and update stamp:" >&2
  echo "  make generate-clients" >&2
  echo "  sha256sum api/openapi.yaml | awk '{print \$1}' > clients/.openapi-sha256" >&2
  exit 1
fi

echo "OpenAPI spec matches clients/.openapi-sha256"