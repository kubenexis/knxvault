#!/usr/bin/env bash
# Copyright The KNXVault Authors.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENTS="${ROOT}/clients"

required_dirs=(python typescript java rust)
for dir in "${required_dirs[@]}"; do
  if [[ ! -d "${CLIENTS}/${dir}" ]]; then
    echo "missing generated client directory: clients/${dir}" >&2
    echo "run: make generate-clients" >&2
    exit 1
  fi
done

markers=(
  "python/.generated"
  "typescript/.generated"
  "java/.generated"
  "rust/.generated"
)
for marker in "${markers[@]}"; do
  if [[ ! -f "${CLIENTS}/${marker}" ]]; then
    echo "missing client marker: clients/${marker}" >&2
    exit 1
  fi
done

echo "client SDK trees present (python, typescript, java, rust)"