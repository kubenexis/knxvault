#!/usr/bin/env bash
# Chaos script: kill Raft leader pod twice and verify cluster recovers.
set -euo pipefail

NAMESPACE="${KNXVAULT_NAMESPACE:-knxvault}"
LABEL="app.kubernetes.io/name=knxvault"

leader_pod() {
  kubectl get pods -n "${NAMESPACE}" -l "${LABEL}" -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}' | awk '{print $1}'
}

echo "Killing leader pod: $(leader_pod)"
kubectl delete pod -n "${NAMESPACE}" "$(leader_pod)" --wait=false
sleep 30
echo "Killing leader pod again: $(leader_pod)"
kubectl delete pod -n "${NAMESPACE}" "$(leader_pod)" --wait=false
sleep 45
kubectl wait --for=condition=ready pod -l "${LABEL}" -n "${NAMESPACE}" --timeout=180s
curl -fsS "http://localhost:8200/ready" | grep -q '"ready":true' && echo "Cluster recovered"