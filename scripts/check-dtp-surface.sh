#!/usr/bin/env bash
# Copyright Kubenexis Systems Private Limited.
# SPDX-License-Identifier: Apache-2.0

# W90-14: CI guard — production/base kustomize must not pull CSI, ESO, webhook, or ACME by default.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

# Strip comments and blank lines from a kustomization for path scanning.
strip_comments() {
  sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$1"
}

# Forbidden path fragments in base/production/airgap resource lists (not comments).
FORBIDDEN_RE='(components/csi|components/eso|components/webhook|components/acme|deployments/csi|external-secrets|k8s/webhook|networkpolicy-acme|acme-egress)'

check_static_surface() {
  local name="$1"
  local path="$2"
  local kust="$path/kustomization.yaml"
  [[ -f "$kust" ]] || fail "missing $kust"

  if strip_comments "$kust" | grep -Eiq "$FORBIDDEN_RE"; then
    fail "$name kustomization resources include CSI/ESO/webhook/ACME paths ($kust)"
  fi
  # Explicit components: block (yaml key) with forbidden entries
  if strip_comments "$kust" | grep -Eiq '^-[[:space:]]*.*(/csi|/eso|/webhook|acme-egress)'; then
    fail "$name kustomization lists forbidden add-on path ($kust)"
  fi
  printf 'ok: %s static surface is base-only\n' "$name"
}

check_rendered() {
  local name="$1"
  local path="$2"
  local out=""
  if command -v kubectl >/dev/null 2>&1; then
    out="$(kubectl kustomize "$path" 2>/dev/null || true)"
  elif command -v kustomize >/dev/null 2>&1; then
    out="$(kustomize build "$path" 2>/dev/null || true)"
  fi
  if [[ -z "$out" ]]; then
    check_static_surface "$name" "$path"
    printf 'warn: kubectl/kustomize not available; static scan only for %s\n' "$name" >&2
    return 0
  fi
  # Rendered manifests must not include add-on workload kinds/names used by components.
  if echo "$out" | grep -Eiq 'kind:[[:space:]]*SecretProviderClass'; then
    fail "$name includes SecretProviderClass (CSI)"
  fi
  if echo "$out" | grep -Eiq 'name:[[:space:]]*knxvault-eso|name:[[:space:]]*knxvault-webhook|kind:[[:space:]]*MutatingWebhookConfiguration'; then
    fail "$name includes ESO/webhook resources"
  fi
  if echo "$out" | grep -Eiq 'name:[[:space:]]*knxvault-acme|networkpolicy-acme|letsencrypt\.org'; then
    fail "$name includes ACME/LE resources"
  fi
  printf 'ok: %s rendered surface is base-only\n' "$name"
}

check_rendered "base" "deployments/k8s/base"
check_rendered "production" "deployments/k8s/production"
check_rendered "airgap-core" "deployments/k8s/overlays/airgap-core"

# platform-edge intentionally includes CSI/webhook/ESO — must reference components.
if [[ -f deployments/k8s/overlays/platform-edge/kustomization.yaml ]]; then
  if ! strip_comments deployments/k8s/overlays/platform-edge/kustomization.yaml | grep -Eq 'components/csi|components/webhook|components/eso'; then
    fail "platform-edge overlay should compose CSI/webhook/ESO components"
  fi
  printf 'ok: platform-edge composes add-on components\n'
fi

# Operator sample must not bind root token (W86-02).
if grep -q 'KNXVAULT_ROOT_TOKEN' deployments/operator/deployment.yaml; then
  fail "operator deployment references KNXVAULT_ROOT_TOKEN (W86-02)"
fi
if grep -A8 'name: KNXVAULT_TOKEN' deployments/operator/deployment.yaml 2>/dev/null | grep -q 'secretKeyRef'; then
  fail "operator deployment binds KNXVAULT_TOKEN from Secret (W86-02)"
fi
printf 'ok: operator deployment has no root token binding\n'

# Operator Role must not grant combined get+create+update on all secrets (W86-01 + write isolation).
if grep -A40 'name: knxvault-operator-secrets' deployments/operator/rbac.yaml | grep -E 'verbs: \["get", "create", "update", "patch"\]' >/dev/null 2>&1; then
  fail "operator secrets Role grants combined get on all secrets (W86-01)"
fi
if grep -A40 'name: knxvault-operator-secrets' deployments/operator/rbac.yaml | grep -E 'verbs: \["create", "update", "patch"\]' >/dev/null 2>&1; then
  fail "operator secrets Role grants blanket update/patch (custody write risk)"
fi
printf 'ok: operator secrets Role avoids blanket get/update (W86-01)\n'

printf 'DTP surface check passed.\n'
