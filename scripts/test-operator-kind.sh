#!/usr/bin/env bash
# Copyright Kubenexis Systems Private Limited.
# SPDX-License-Identifier: Apache-2.0

# kind-oriented operator smoke (W30-07). Requires kubectl context and vault at KNXVAULT_ADDR.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${KNXVAULT_ADDR:=http://127.0.0.1:8200}"
: "${KNXVAULT_TOKEN:=dev-root-token}"

kubectl apply -f "$ROOT/deployments/operator/crds/"
kubectl apply -f "$ROOT/deployments/operator/rbac.yaml"
kubectl get ns knxvault 2>/dev/null || kubectl create ns knxvault

if ! pgrep -f knxvault-operator >/dev/null 2>&1; then
  make -C "$ROOT" build-operator
  KNXVAULT_ADDR="$KNXVAULT_ADDR" KNXVAULT_TOKEN="$KNXVAULT_TOKEN" \
    KNXVAULT_OPERATOR_INGRESS_SHIM=true \
    nohup "$ROOT/build/bin/knxvault-operator" >/tmp/knxvault-operator.log 2>&1 &
  sleep 3
fi

kubectl apply -f "$ROOT/deployments/operator/samples/certificate-example.yaml"
for i in $(seq 1 60); do
  if kubectl -n default get secret app-tls >/dev/null 2>&1; then
    echo "PASS: operator kind smoke"
    exit 0
  fi
  sleep 2
done
echo "FAIL"; kubectl -n default get knxvaultcertificate -o yaml; tail -50 /tmp/knxvault-operator.log; exit 1
