#!/usr/bin/env bash
# Lab e2e: knxvault + operator CRDs without cert-manager.
# Usage: bash scripts/lab-operator-e2e.sh [host]
# Default: 192.168.137.131  (192.168.137.37 often has no SSH)
set -euo pipefail

HOST="${1:-192.168.137.131}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOKEN_FILE=/opt/knxvault/e2e-root.token
TOKEN_VALUE=e2e-root-token-lab

echo "==> target $HOST"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=12 "root@${HOST}" 'hostname; kubectl get nodes'

echo "==> build"
make -C "$ROOT" build build-cli build-operator

echo "==> stop old processes and install binaries"
ssh "root@${HOST}" "bash -s" <<'STOP'
set +e
# Kill only vault/operator by matching command line path (not this SSH shell).
ps -eo pid=,args= | awk '
  $0 ~ /\/opt\/knxvault\/knxvault serve/ { print $1 }
  $0 ~ /\/opt\/knxvault\/knxvault-operator/ { print $1 }
' | while read -r pid; do kill -9 "$pid" 2>/dev/null; done
sleep 2
mkdir -p /opt/knxvault /var/lib/knxvault/raft-op /var/log/knxvault
rm -f /opt/knxvault/knxvault /opt/knxvault/knxvault-cli /opt/knxvault/knxvault-operator
STOP

scp -o StrictHostKeyChecking=no \
  "$ROOT/bin/knxvault" "$ROOT/bin/knxvault-cli" "$ROOT/bin/knxvault-operator" \
  "root@${HOST}:/opt/knxvault/"
ssh "root@${HOST}" 'chmod +x /opt/knxvault/knxvault /opt/knxvault/knxvault-cli /opt/knxvault/knxvault-operator'

echo "==> CRDs + RBAC"
scp -r "$ROOT/deployments/operator" "root@${HOST}:/tmp/knxvault-operator-deploy"
ssh "root@${HOST}" 'kubectl get ns knxvault >/dev/null 2>&1 || kubectl create ns knxvault
kubectl apply -f /tmp/knxvault-operator-deploy/crds/
kubectl apply -f /tmp/knxvault-operator-deploy/rbac.yaml'

echo "==> start vault (fresh raft dir) + operator"
ssh "root@${HOST}" "bash -s" <<REMOTE
set -euo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf
rm -rf /var/lib/knxvault/raft-op && mkdir -p /var/lib/knxvault/raft-op
openssl rand -base64 32 > /opt/knxvault/e2e-master.key
openssl rand -base64 32 > /opt/knxvault/e2e-unseal.key
echo '${TOKEN_VALUE}' > ${TOKEN_FILE}
chmod 600 /opt/knxvault/e2e-*.key ${TOKEN_FILE}
export KNXVAULT_MASTER_KEY="\$(cat /opt/knxvault/e2e-master.key)"
export KNXVAULT_UNSEAL_KEY="\$(cat /opt/knxvault/e2e-unseal.key)"
export KNXVAULT_ROOT_TOKEN='${TOKEN_VALUE}'
export KNXVAULT_HTTP_ADDR=':8200'
export KNXVAULT_RAFT_ENABLED=true
export KNXVAULT_RAFT_NODE_ID=1
export KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001
export KNXVAULT_RAFT_DATA_DIR=/var/lib/knxvault/raft-op
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001
nohup /opt/knxvault/knxvault serve > /var/log/knxvault/op-serve.log 2>&1 &
for i in \$(seq 1 60); do
  curl -sf http://127.0.0.1:8200/ready >/dev/null && break
  sleep 1
done
curl -sf http://127.0.0.1:8200/health; echo

export KNXVAULT_ADDR=http://127.0.0.1:8200
export KNXVAULT_TOKEN='${TOKEN_VALUE}'
export KNXVAULT_OPERATOR_INGRESS_SHIM=true
export KNXVAULT_OPERATOR_LEADER_ELECT=false
export KNXVAULT_OPERATOR_METRICS_ADDR=:18080
export KNXVAULT_OPERATOR_PROBE_ADDR=:18081
nohup /opt/knxvault/knxvault-operator > /var/log/knxvault/operator.log 2>&1 &
sleep 3
pgrep -af '/opt/knxvault/knxvault' || { echo fail start; tail -40 /var/log/knxvault/operator.log; exit 1; }

kubectl delete knxvaultcertificate,knxvaultca,knxvaultclusterissuer --all -A --ignore-not-found
kubectl delete secret app-tls -n default --ignore-not-found
sleep 1
kubectl apply -f /tmp/knxvault-operator-deploy/samples/certificate-example.yaml

for i in \$(seq 1 60); do
  ready=\$(kubectl get knxvaultclusterissuer platform -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  serial=\$(kubectl -n default get knxvaultcertificate app-tls -o jsonpath='{.status.serial}' 2>/dev/null || true)
  caid=\$(kubectl -n default get knxvaultcertificate app-tls -o jsonpath='{.status.caId}' 2>/dev/null || true)
  if [ "\$ready" = "True" ] && [ -n "\$serial" ] && [ -n "\$caid" ] && kubectl -n default get secret app-tls >/dev/null 2>&1; then
    echo "E2E PASS ready=\$ready serial=\$serial caId=\$caid"
    kubectl -n default get secret app-tls -o jsonpath='{.metadata.annotations}'; echo
    kubectl -n knxvault get knxvaultca platform-root -o jsonpath='{.status.conditions[0].message}'; echo
    exit 0
  fi
  sleep 2
done
echo E2E FAIL
kubectl get knxvaultclusterissuer platform -o yaml | tail -20
kubectl -n default get knxvaultcertificate app-tls -o yaml | tail -30
tail -40 /var/log/knxvault/operator.log
tail -20 /var/log/knxvault/op-serve.log
exit 1
REMOTE

echo "==> LAB OPERATOR E2E PASS on $HOST"
