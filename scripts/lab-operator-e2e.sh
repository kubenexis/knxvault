#!/usr/bin/env bash
# Lab e2e: knxvault + operator CRDs without cert-manager (W30-07).
# Usage: bash scripts/lab-operator-e2e.sh [host]
# Default host: 192.168.137.131. Note: 192.168.137.37 may block SSH (ICMP only).
set -euo pipefail

HOST="${1:-192.168.137.131}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=knxvault

echo "==> target host $HOST"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "root@${HOST}" 'hostname; kubectl get nodes'

echo "==> build binaries"
make -C "$ROOT" build build-cli build-operator

echo "==> scp binaries"
ssh "root@${HOST}" 'mkdir -p /opt/knxvault /var/lib/knxvault/raft-op /var/log/knxvault
# Force-stop by PID (killall name length can miss knxvault-operator)
for bin in /opt/knxvault/knxvault /opt/knxvault/knxvault-operator; do
  for pid in $(pidof -x "$bin" 2>/dev/null); do kill -9 "$pid" 2>/dev/null || true; done
done
# fallback: any process whose cmdline contains the path
ps -eo pid=,args= | while read -r pid args; do
  case "$args" in
    */opt/knxvault/knxvault\ serve*|*/opt/knxvault/knxvault-operator*) kill -9 "$pid" 2>/dev/null || true ;;
  esac
done
sleep 2
rm -f /opt/knxvault/knxvault /opt/knxvault/knxvault-cli /opt/knxvault/knxvault-operator'
scp -o StrictHostKeyChecking=no \
  "$ROOT/bin/knxvault" "$ROOT/bin/knxvault-cli" "$ROOT/bin/knxvault-operator" \
  "root@${HOST}:/opt/knxvault/"

echo "==> apply CRDs + RBAC"
scp -r "$ROOT/deployments/operator" "root@${HOST}:/tmp/knxvault-operator-deploy"
ssh "root@${HOST}" 'kubectl get ns knxvault 2>/dev/null || kubectl create ns knxvault; kubectl apply -f /tmp/knxvault-operator-deploy/crds/; kubectl apply -f /tmp/knxvault-operator-deploy/rbac.yaml'

echo "==> start single-node vault if needed"
ssh "root@${HOST}" 'bash -s' <<'REMOTE'
set -euo pipefail
if ! curl -sf http://127.0.0.1:8200/health >/dev/null 2>&1; then
  pgrep -x knxvault >/dev/null && kill $(pgrep -x knxvault) || true
  sleep 1
  openssl rand -base64 32 > /opt/knxvault/e2e-master.key
  openssl rand -base64 32 > /opt/knxvault/e2e-unseal.key
  echo 'e2e-root-token-op' > /opt/knxvault/e2e-root.token
  chmod 600 /opt/knxvault/e2e-*.key /opt/knxvault/e2e-root.token
  rm -rf /var/lib/knxvault/raft-op && mkdir -p /var/lib/knxvault/raft-op
  export KNXVAULT_MASTER_KEY="$(cat /opt/knxvault/e2e-master.key)"
  export KNXVAULT_UNSEAL_KEY="$(cat /opt/knxvault/e2e-unseal.key)"
  export KNXVAULT_ROOT_TOKEN="$(cat /opt/knxvault/e2e-root.token)"
  export KNXVAULT_HTTP_ADDR=':8200'
  export KNXVAULT_RAFT_ENABLED=true
  export KNXVAULT_RAFT_NODE_ID=1
  export KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001
  export KNXVAULT_RAFT_DATA_DIR=/var/lib/knxvault/raft-op
  export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001
  nohup /opt/knxvault/knxvault serve > /var/log/knxvault/op-serve.log 2>&1 &
  for i in $(seq 1 60); do
    curl -sf http://127.0.0.1:8200/health >/dev/null && break
    sleep 1
  done
  curl -sf http://127.0.0.1:8200/ready
  echo
fi
# ensure token file for operator
test -f /opt/knxvault/e2e-root.token || echo 'e2e-root-token-op' > /opt/knxvault/e2e-root.token
REMOTE

echo "==> start operator (host process with cluster kubeconfig)"
ssh "root@${HOST}" 'bash -s' <<'REMOTE'
set -euo pipefail
pkill -x knxvault-operator 2>/dev/null || true
sleep 1
export KUBECONFIG=/etc/kubernetes/admin.conf
export KNXVAULT_ADDR=http://127.0.0.1:8200
export KNXVAULT_TOKEN=$(cat /opt/knxvault/e2e-root.token)
export KNXVAULT_OPERATOR_INGRESS_SHIM=true
export KNXVAULT_OPERATOR_LEADER_ELECT=false
export KNXVAULT_OPERATOR_METRICS_ADDR=:18080
export KNXVAULT_OPERATOR_PROBE_ADDR=:18081
nohup /opt/knxvault/knxvault-operator > /var/log/knxvault/operator.log 2>&1 &
sleep 3
pgrep -af knxvault-operator || { echo operator failed; tail -50 /var/log/knxvault/operator.log; exit 1; }
REMOTE

echo "==> apply samples"
ssh "root@${HOST}" 'kubectl apply -f /tmp/knxvault-operator-deploy/samples/certificate-example.yaml'

echo "==> wait for Ready / Secret"
ssh "root@${HOST}" 'bash -s' <<'REMOTE'
set -euo pipefail
for i in $(seq 1 90); do
  serial=$(kubectl -n default get knxvaultcertificate app-tls -o jsonpath='{.status.serial}' 2>/dev/null || true)
  if kubectl -n default get secret app-tls >/dev/null 2>&1 && [[ -n "$serial" ]]; then
    echo "PASS: secret app-tls serial=$serial"
    kubectl -n default get knxvaultcertificate app-tls -o wide
    kubectl -n knxvault get knxvaultca platform-root -o yaml | head -40
    kubectl get knxvaultclusterissuer platform -o yaml | head -30
    exit 0
  fi
  sleep 2
done
echo "FAIL: timeout"
kubectl -n default get knxvaultcertificate app-tls -o yaml || true
kubectl -n knxvault get knxvaultca -o yaml || true
tail -80 /var/log/knxvault/operator.log || true
tail -40 /var/log/knxvault/op-serve.log || true
exit 1
REMOTE

echo "==> LAB OPERATOR E2E PASS on $HOST (no cert-manager)"
