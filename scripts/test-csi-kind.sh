#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-knxvault-csi}"

if ! command -v kind >/dev/null 2>&1; then
  echo "kind is required" >&2
  exit 1
fi

make -C "$ROOT" build-csi

if ! kind get clusters | grep -qx "$CLUSTER_NAME"; then
  kind create cluster --name "$CLUSTER_NAME"
fi

kubectl config use-context "kind-${CLUSTER_NAME}"

echo "Install Secrets Store CSI Driver manifest (user cluster may use Helm instead)"
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/secrets-store-csi-driver/v1.4.6/deploy/secrets-store-csi-driver.yaml

kubectl create namespace knxvault --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "$ROOT/deployments/csi/rbac.yaml"
kubectl apply -f "$ROOT/deployments/csi/k8s-provider.yaml"

echo "Waiting for knxvault-csi provider pod"
kubectl -n knxvault rollout status daemonset/knxvault-csi-provider --timeout=120s || true

echo "CSI kind E2E prerequisites applied."
echo "  - Driver + RBAC + provider daemonset"
echo "  - KV mount assertion: make test-integration (TestCSIProviderMountIntegration)"