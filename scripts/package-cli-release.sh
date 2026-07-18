#!/usr/bin/env bash
# Copyright Kubenexis Systems Private Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Cross-compile knxvault-cli and package platform archives for GitHub Releases.
# Output: build/release/cli/knxvault-cli_<version>_<os>_<arch>.tar.gz|.zip + SHA256SUMS
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-0.5.1}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_ID="${BUILD_ID:-$(date +%s)}"
GO_TOOLCHAIN="${GO_TOOLCHAIN:-go1.26.5}"
export GOTOOLCHAIN="$GO_TOOLCHAIN"

OUT_DIR="${CLI_RELEASE_DIR:-build/release/cli}"
STAGING="${OUT_DIR}/.staging"
LDFLAGS="-s -w \
  -X github.com/kubenexis/knxvault/internal/version.Version=${VERSION} \
  -X github.com/kubenexis/knxvault/internal/version.Commit=${COMMIT} \
  -X github.com/kubenexis/knxvault/internal/version.BuildID=${BUILD_ID}"

# os/arch pairs (GOOS/GOARCH)
TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
)

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR" "$STAGING"

build_one() {
  local goos="$1" goarch="$2"
  local ext="" name="knxvault-cli"
  if [[ "$goos" == "windows" ]]; then
    ext=".exe"
  fi
  local outbin="${STAGING}/${name}-${goos}-${goarch}${ext}"
  echo "==> Building ${name} ${goos}/${goarch}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags="$LDFLAGS" -o "$outbin" ./cmd/knxvault-cli

  local pkg_root="${STAGING}/pkg-${goos}-${goarch}"
  mkdir -p "$pkg_root"
  cp "$outbin" "${pkg_root}/${name}${ext}"
  cp LICENSE "${pkg_root}/LICENSE"
  cat > "${pkg_root}/README.txt" <<EOF
KNXVault CLI (knxvault-cli)
Version: ${VERSION}
Commit:  ${COMMIT}
OS/Arch: ${goos}/${goarch}

Admin host binary — not a container image.
Never bake into the knxvault server image.

Docs: https://github.com/kubenexis/knxvault/blob/main/docs/cli/reference.md
Quick start:
  export KNXVAULT_ADDR=https://knxvault.example:8200
  export KNXVAULT_TOKEN=<token>
  ./${name}${ext} doctor --profile production
EOF

  local archive
  if [[ "$goos" == "windows" ]]; then
    archive="${OUT_DIR}/knxvault-cli_${VERSION}_${goos}_${goarch}.zip"
    # Prefer zip(1); fall back to Python (CI images may lack zip).
    if command -v zip >/dev/null 2>&1; then
      (cd "$pkg_root" && zip -q -r "$ROOT/$archive" .)
    else
      python3 - "$pkg_root" "$ROOT/$archive" <<'PY'
import os, sys, zipfile
root, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
    for dirpath, _, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            zf.write(path, os.path.relpath(path, root))
PY
    fi
  else
    archive="${OUT_DIR}/knxvault-cli_${VERSION}_${goos}_${goarch}.tar.gz"
    tar -C "$pkg_root" -czf "$archive" .
  fi
  echo "    -> ${archive}"
}

for t in "${TARGETS[@]}"; do
  build_one "${t%/*}" "${t#*/}"
done

# Checksums (portable)
(
  cd "$OUT_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum knxvault-cli_* > SHA256SUMS
  else
    shasum -a 256 knxvault-cli_* > SHA256SUMS
  fi
)

# Build info
cat > "${OUT_DIR}/build-info.txt" <<EOF
package=knxvault-cli
version=${VERSION}
commit=${COMMIT}
build_id=${BUILD_ID}
targets=${TARGETS[*]}
EOF

rm -rf "$STAGING"
echo "==> CLI release packages in ${OUT_DIR}"
ls -la "$OUT_DIR"
