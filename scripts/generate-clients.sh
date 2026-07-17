#!/usr/bin/env bash
# Copyright The KNXVault Authors.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${ROOT}/api/openapi.yaml"
IMAGE="${OPENAPI_GENERATOR_IMAGE:-openapitools/openapi-generator-cli:v7.10.0}"
OUT="${ROOT}/clients"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run openapi-generator" >&2
  exit 1
fi

gen() {
  local generator="$1"
  local output="$2"
  local extra="${3:-}"
  echo "==> generating ${generator} -> ${output}"
  docker run --rm \
    -v "${ROOT}:/local" \
    -w /local \
    "${IMAGE}" generate \
    -i /local/api/openapi.yaml \
    -g "${generator}" \
    -o "/local/clients/${output}" \
    --package-name knxvault \
    ${extra}
}

mkdir -p "${OUT}"

gen python python \
  "--additional-properties=packageName=knxvault,projectName=knxvault-client"

gen typescript-axios typescript \
  "--additional-properties=npmName=@knxvault/client,supportsES6=true"

gen java java \
  "--additional-properties=groupId=dev.knxvault,artifactId=knxvault-client,library=okhttp-gson"

gen rust rust \
  "--additional-properties=packageName=knxvault-client"

for lang in python typescript java rust; do
  date -u +"%Y-%m-%dT%H:%M:%SZ" > "${OUT}/${lang}/.generated"
done
sha256sum "${SPEC}" | awk '{print $1}' > "${OUT}/.openapi-sha256"

echo "Go client: maintain pkg/client manually (reference implementation)."
echo "Done. Review clients/ before commit."