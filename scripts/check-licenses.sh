#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Enforces the permissive license allow-list (docs/licensing.md, LLD §1.5).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GOTOOLCHAIN="${GO_TOOLCHAIN:-go1.25.11}"

cd "${ROOT}"
echo "==> Checking dependency licenses (see config/licenses.allow)"
go run ./scripts/check-licenses