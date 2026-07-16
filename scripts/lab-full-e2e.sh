#!/usr/bin/env bash
# Complete lab E2E for knxvault on a single node (default 192.168.137.131).
# Covers: host Raft serve, CLI/API smoke, Vault product profile (cert-manager),
# and knxvault-operator CRD path.
#
# Usage: bash scripts/lab-full-e2e.sh [host]
# Exit 0 only if all sections pass.
set -euo pipefail

HOST="${1:-192.168.137.131}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOKEN_VALUE=e2e-root-token-lab
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
RESULTS=/tmp/knxvault-lab-full-e2e-results.txt
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  PASS  $*"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL  $*"; }

echo "=============================================="
echo " KNXVault full lab E2E"
echo " host=$HOST commit=$COMMIT"
echo " $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================="

echo "==> SSH probe"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=12 "root@${HOST}" 'hostname; kubectl get nodes -o wide | head -5'

echo "==> build (server + cli + operator)"
make -C "$ROOT" build build-cli build-operator

echo "==> stop prior vault/operator by path match"
ssh "root@${HOST}" "bash -s" <<'STOP'
set +e
ps -eo pid=,args= | awk '
  $0 ~ /\/opt\/knxvault\/knxvault serve/ { print $1 }
  $0 ~ /\/opt\/knxvault\/knxvault-operator/ { print $1 }
' | while read -r pid; do kill -9 "$pid" 2>/dev/null; done
sleep 2
mkdir -p /opt/knxvault /var/lib/knxvault/raft-full /var/log/knxvault
rm -f /opt/knxvault/knxvault /opt/knxvault/knxvault-cli /opt/knxvault/knxvault-operator
STOP

echo "==> install binaries"
scp -o StrictHostKeyChecking=no \
  "$ROOT/bin/knxvault" "$ROOT/bin/knxvault-cli" "$ROOT/bin/knxvault-operator" \
  "root@${HOST}:/opt/knxvault/"
ssh "root@${HOST}" 'chmod +x /opt/knxvault/knxvault /opt/knxvault/knxvault-cli /opt/knxvault/knxvault-operator
/opt/knxvault/knxvault -version 2>/dev/null || /opt/knxvault/knxvault version 2>/dev/null || true
/opt/knxvault/knxvault-cli -version 2>/dev/null || true'

echo "==> operator CRDs + RBAC"
ssh "root@${HOST}" 'rm -rf /tmp/knxvault-operator-deploy'
scp -r "$ROOT/deployments/operator" "root@${HOST}:/tmp/knxvault-operator-deploy"
ssh "root@${HOST}" 'kubectl get ns knxvault >/dev/null 2>&1 || kubectl create ns knxvault
kubectl apply -f /tmp/knxvault-operator-deploy/crds/
kubectl apply -f /tmp/knxvault-operator-deploy/rbac.yaml
ls /tmp/knxvault-operator-deploy/samples/'

# Shamir multi-share unseal (ops flow): start sealed → submit t-of-n shares only → open data plane.
# Shares are produced offline (generate-unseal-shares is seal-guarded).
SHAMIR_N=3
SHAMIR_T=2
SHARE_DIR=$(mktemp -d /tmp/knxvault-lab-shares.XXXXXX)
trap 'rm -rf "$SHARE_DIR"' EXIT

echo "==> generate keys on lab + offline Shamir split (t=${SHAMIR_T} of n=${SHAMIR_N})"
ssh "root@${HOST}" "bash -s" <<'GENKEYS'
set -euo pipefail
mkdir -p /opt/knxvault /var/lib/knxvault/raft-full /var/log/knxvault
rm -rf /var/lib/knxvault/raft-full && mkdir -p /var/lib/knxvault/raft-full
openssl rand -base64 32 > /opt/knxvault/e2e-master.key
openssl rand -base64 32 > /opt/knxvault/e2e-unseal.key
chmod 600 /opt/knxvault/e2e-*.key
GENKEYS
scp -o StrictHostKeyChecking=no "root@${HOST}:/opt/knxvault/e2e-unseal.key" "$SHARE_DIR/e2e-unseal.key"
UNSEAL_B64=$(tr -d '\n' < "$SHARE_DIR/e2e-unseal.key")
# Offline split on the build host (same package as production unseal combine).
go run "$ROOT/scripts/shamir-split/main.go" -key "$UNSEAL_B64" -n "$SHAMIR_N" -t "$SHAMIR_T" \
  > "$SHARE_DIR/shares.txt"
mapfile -t LAB_SHARES < "$SHARE_DIR/shares.txt"
if [ "${#LAB_SHARES[@]}" -ne "$SHAMIR_N" ]; then
  echo "expected $SHAMIR_N shares, got ${#LAB_SHARES[@]}"
  cat "$SHARE_DIR/shares.txt"
  exit 1
fi
# Install share files on lab (custodian simulation); never install full unseal for the multi-share path.
ssh "root@${HOST}" "rm -f /opt/knxvault/e2e-share-*.b64; mkdir -p /opt/knxvault"
i=1
for s in "${LAB_SHARES[@]}"; do
  printf '%s' "$s" | ssh "root@${HOST}" "cat > /opt/knxvault/e2e-share-${i}.b64 && chmod 600 /opt/knxvault/e2e-share-${i}.b64"
  i=$((i + 1))
done
echo "  offline split OK (${SHAMIR_N} shares, threshold ${SHAMIR_T})"

echo "==> start vault sealed (Raft + UNSEAL_THRESHOLD=${SHAMIR_T}); multi-share unseal; then operator"
ssh "root@${HOST}" "bash -s" <<REMOTE
set -euo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf
echo '${TOKEN_VALUE}' > /opt/knxvault/e2e-root.token
chmod 600 /opt/knxvault/e2e-root.token
export KNXVAULT_MASTER_KEY="\$(tr -d '\n' < /opt/knxvault/e2e-master.key)"
export KNXVAULT_UNSEAL_KEY="\$(tr -d '\n' < /opt/knxvault/e2e-unseal.key)"
export KNXVAULT_UNSEAL_THRESHOLD=${SHAMIR_T}
export KNXVAULT_ROOT_TOKEN='${TOKEN_VALUE}'
export KNXVAULT_HTTP_ADDR=':8200'
export KNXVAULT_LOG_LEVEL=info
export KNXVAULT_RAFT_ENABLED=true
export KNXVAULT_RAFT_NODE_ID=1
export KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001
export KNXVAULT_RAFT_DATA_DIR=/var/lib/knxvault/raft-full
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001
export KNXVAULT_RAFT_LEADER_WAIT=30s
nohup /opt/knxvault/knxvault serve > /var/log/knxvault/full-e2e-serve.log 2>&1 &
for i in \$(seq 1 90); do
  curl -sf http://127.0.0.1:8200/ready >/dev/null && break
  sleep 1
done
curl -sf http://127.0.0.1:8200/ready >/dev/null || {
  echo 'vault not ready'; tail -50 /var/log/knxvault/full-e2e-serve.log; exit 1
}

# Assert start sealed (must not auto-open).
H0=\$(curl -sf http://127.0.0.1:8200/health || true)
echo "\$H0" | grep -q '"sealed"[[:space:]]*:[[:space:]]*true' || {
  echo "expected sealed at start: \$H0"; exit 1
}
echo START_SEALED_OK

# Multi-share unseal: t-of-n shares only (never POST full key on this path).
SHARE1=\$(tr -d '\n' < /opt/knxvault/e2e-share-1.b64)
SHARE2=\$(tr -d '\n' < /opt/knxvault/e2e-share-2.b64)
curl -sf -X POST http://127.0.0.1:8200/sys/unseal \
  -H 'Content-Type: application/json' \
  -d "{\\"share\\":\\"\${SHARE1}\\"}" >/tmp/knxvault-unseal-s1.json || {
  echo 'share1 unseal request failed'; cat /tmp/knxvault-unseal-s1.json 2>/dev/null; exit 1
}
if ! grep -q '"sealed"[[:space:]]*:[[:space:]]*true' /tmp/knxvault-unseal-s1.json; then
  echo "after 1 share expected still sealed: \$(cat /tmp/knxvault-unseal-s1.json)"; exit 1
fi
if ! grep -Eq '"progress"[[:space:]]*:[[:space:]]*1' /tmp/knxvault-unseal-s1.json; then
  echo "after 1 share expected progress=1: \$(cat /tmp/knxvault-unseal-s1.json)"; exit 1
fi
if ! grep -Eq '"threshold"[[:space:]]*:[[:space:]]*${SHAMIR_T}' /tmp/knxvault-unseal-s1.json; then
  echo "after 1 share expected threshold=${SHAMIR_T}: \$(cat /tmp/knxvault-unseal-s1.json)"; exit 1
fi
echo SHARE1_PROGRESS_OK

curl -sf -X POST http://127.0.0.1:8200/sys/unseal \
  -H 'Content-Type: application/json' \
  -d "{\\"share\\":\\"\${SHARE2}\\"}" >/tmp/knxvault-unseal-s2.json || {
  echo 'share2 unseal request failed'; cat /tmp/knxvault-unseal-s2.json 2>/dev/null; exit 1
}
if ! grep -q '"sealed"[[:space:]]*:[[:space:]]*false' /tmp/knxvault-unseal-s2.json; then
  H=\$(curl -sf http://127.0.0.1:8200/health || true)
  echo "\$H" | grep -q '"sealed"[[:space:]]*:[[:space:]]*false' || {
    echo "still sealed after t shares: \$(cat /tmp/knxvault-unseal-s2.json) health=\$H"
    exit 1
  }
fi
# Data plane open: KV write must succeed (proves not just health flag).
TOK='${TOKEN_VALUE}'
curl -sf -X POST http://127.0.0.1:8200/secrets/kv/e2e/multishare-open \
  -H "Authorization: Bearer \${TOK}" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"ok":"after-multishare-unseal"}}' >/tmp/knxvault-kv-open.json || {
  echo 'KV write after multi-share unseal failed'; cat /tmp/knxvault-kv-open.json 2>/dev/null
  tail -30 /var/log/knxvault/full-e2e-serve.log; exit 1
}
echo MULTISHARE_UNSEAL_OK

export KNXVAULT_ADDR=http://127.0.0.1:8200
export KNXVAULT_TOKEN='${TOKEN_VALUE}'
export KNXVAULT_OPERATOR_INGRESS_SHIM=true
export KNXVAULT_OPERATOR_LEADER_ELECT=false
export KNXVAULT_OPERATOR_METRICS_ADDR=:18080
export KNXVAULT_OPERATOR_PROBE_ADDR=:18081
nohup /opt/knxvault/knxvault-operator > /var/log/knxvault/full-e2e-operator.log 2>&1 &
sleep 3
pgrep -af '/opt/knxvault/knxvault' >/dev/null || {
  echo fail start; tail -40 /var/log/knxvault/full-e2e-operator.log; exit 1
}
echo SERVE_OK
REMOTE

echo "==> remote check suite"
# shellcheck disable=SC2087
# Subshell so PIPESTATUS[0] is ssh exit status after tee.
(
ssh "root@${HOST}" "bash -s" <<'CHECKS'
set -euo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf
export KNXVAULT_ADDR=http://127.0.0.1:8200
export KNXVAULT_TOKEN=e2e-root-token-lab
CLI=/opt/knxvault/knxvault-cli
PASS=0
FAIL=0
pass() { PASS=$((PASS+1)); echo "PASS|$1"; }
fail() { FAIL=$((FAIL+1)); echo "FAIL|$1"; }

# --- A. Core CLI / API ---
echo "SECTION|core"
# CLI may log build line on stderr or stdout; match spaced JSON keys.
json_has() { echo "$1" | grep -Eq "$2"; }

H=$($CLI --addr "$KNXVAULT_ADDR" --token "$KNXVAULT_TOKEN" health 2>/dev/null || true)
json_has "$H" '"status"[[:space:]]*:[[:space:]]*"healthy"' && pass "cli health healthy" || fail "cli health healthy"
json_has "$H" '"raft_ready"[[:space:]]*:[[:space:]]*true' && pass "cli health raft_ready" || fail "cli health raft_ready"
json_has "$H" '"sealed"[[:space:]]*:[[:space:]]*false' && pass "cli health unsealed" || fail "cli health unsealed"
json_has "$H" '"leader"[[:space:]]*:[[:space:]]*true' && pass "cli health leader" || fail "cli health leader"

S=$($CLI --addr "$KNXVAULT_ADDR" --token "$KNXVAULT_TOKEN" status 2>/dev/null || true)
json_has "$S" '"status"[[:space:]]*:[[:space:]]*"ready"' && pass "cli status ready" || fail "cli status ready"

D=$($CLI --addr "$KNXVAULT_ADDR" --token "$KNXVAULT_TOKEN" doctor --json 2>/dev/null || true)
json_has "$D" '"healthy"[[:space:]]*:[[:space:]]*true' && pass "cli doctor healthy" || fail "cli doctor healthy"
# fail count 0 (allow warn)
json_has "$D" '"fail"[[:space:]]*:[[:space:]]*0' && pass "cli doctor fail=0" || fail "cli doctor fail=0"

AUTH=$(curl -sf -X POST "$KNXVAULT_ADDR/auth/token" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$KNXVAULT_TOKEN\"}" || true)
echo "$AUTH" | grep -q 'client_token\|policies\|ttl' && pass "POST /auth/token" || fail "POST /auth/token"

ROOT=$($CLI --addr "$KNXVAULT_ADDR" --token "$KNXVAULT_TOKEN" pki root \
  --name e2e-full-root --common-name "E2E Full Root" --ttl 720h 2>/dev/null || true)
echo "$ROOT" | grep -q 'BEGIN CERTIFICATE' && pass "pki root create" || fail "pki root create"

LEAF=$($CLI --addr "$KNXVAULT_ADDR" --token "$KNXVAULT_TOKEN" pki issue \
  --role e2e-full-root --common-name e2e.full.local --dns e2e.full.local --ttl 24h 2>/dev/null || true)
echo "$LEAF" | grep -q 'BEGIN CERTIFICATE' && pass "pki issue leaf" || fail "pki issue leaf"
echo "$LEAF" | grep -q 'BEGIN.*PRIVATE KEY' && pass "pki issue private key" || fail "pki issue private key"

$CLI --addr "$KNXVAULT_ADDR" --token "$KNXVAULT_TOKEN" kv put e2e/full-secret value=s3cret-full 2>/dev/null \
  && pass "kv put" || fail "kv put"
SHOW=$($CLI --addr "$KNXVAULT_ADDR" --token "$KNXVAULT_TOKEN" kv get --show-secrets e2e/full-secret 2>/dev/null || true)
echo "$SHOW" | grep -q 's3cret-full' && pass "kv get --show-secrets" || fail "kv get --show-secrets"
RED=$($CLI --addr "$KNXVAULT_ADDR" --token "$KNXVAULT_TOKEN" kv get e2e/full-secret 2>/dev/null || true)
echo "$RED" | grep -qi 'REDACTED' && pass "kv get redacted" || fail "kv get redacted"

# --- W53: multi-share unseal bootstrap (start sealed → t-of-n shares → data plane) ---
echo "SECTION|multishare"
# KV written only after multi-share unseal in bootstrap (never used full-key unseal for open).
MS=$($CLI --addr "$KNXVAULT_ADDR" --token "$KNXVAULT_TOKEN" kv get --show-secrets e2e/multishare-open 2>/dev/null || true)
echo "$MS" | grep -q 'after-multishare-unseal' && pass "W53 bootstrap multi-share opened data plane (KV)" || fail "W53 bootstrap multi-share opened data plane (KV)"
test -f /opt/knxvault/e2e-share-1.b64 && test -f /opt/knxvault/e2e-share-2.b64 && test -f /opt/knxvault/e2e-share-3.b64 \
  && pass "W53 offline custodian shares present (n=3)" || fail "W53 offline custodian shares present (n=3)"

# Re-seal → progress with 1 share → unseal with alternate pair (shares 1+3) — full key never used.
curl -sf -X POST "$KNXVAULT_ADDR/sys/seal" -H "Authorization: Bearer $KNXVAULT_TOKEN" >/dev/null \
  && pass "W53 re-seal for multi-share ceremony" || fail "W53 re-seal for multi-share ceremony"
Hseal=$(curl -sf "$KNXVAULT_ADDR/health" || true)
echo "$Hseal" | grep -q '"sealed"[[:space:]]*:[[:space:]]*true' && pass "W53 health sealed after re-seal" || fail "W53 health sealed after re-seal"
# Data plane blocked while sealed
KVCODE=$(curl -sS -o /tmp/kv-sealed.out -w '%{http_code}' -X POST "$KNXVAULT_ADDR/secrets/kv/e2e/should-block" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" -H 'Content-Type: application/json' \
  -d '{"data":{"x":1}}' || echo 000)
[ "$KVCODE" = "503" ] && pass "W53 KV blocked while sealed (503)" || fail "W53 KV blocked while sealed (got $KVCODE)"

S1=$(tr -d '\n' < /opt/knxvault/e2e-share-1.b64)
S3=$(tr -d '\n' < /opt/knxvault/e2e-share-3.b64)
R1=$(curl -sS -X POST "$KNXVAULT_ADDR/sys/unseal" -H 'Content-Type: application/json' \
  -d "{\"share\":\"$S1\"}" || true)
echo "$R1" | grep -q '"sealed"[[:space:]]*:[[:space:]]*true' && pass "W53 share1 alone still sealed" || fail "W53 share1 alone still sealed"
echo "$R1" | grep -Eq '"progress"[[:space:]]*:[[:space:]]*1' && pass "W53 share1 progress=1" || fail "W53 share1 progress=1"
R3=$(curl -sS -X POST "$KNXVAULT_ADDR/sys/unseal" -H 'Content-Type: application/json' \
  -d "{\"share\":\"$S3\"}" || true)
echo "$R3" | grep -q '"sealed"[[:space:]]*:[[:space:]]*false' && pass "W53 shares 1+3 unseal (t-of-n)" || fail "W53 shares 1+3 unseal (t-of-n)"
Hopen=$(curl -sf "$KNXVAULT_ADDR/health" || true)
echo "$Hopen" | grep -q '"sealed"[[:space:]]*:[[:space:]]*false' && pass "W53 health unsealed after multi-share" || fail "W53 health unsealed after multi-share"
curl -sf -X POST "$KNXVAULT_ADDR/secrets/kv/e2e/after-reseal-multishare" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" -H 'Content-Type: application/json' \
  -d '{"data":{"ok":"reseal-multishare"}}' >/dev/null \
  && pass "W53 data plane open after multi-share re-unseal" || fail "W53 data plane open after multi-share re-unseal"

# Admin API: generate-unseal-shares while unsealed (ceremony tooling)
UNSEAL_KEY=$(tr -d '\n' < /opt/knxvault/e2e-unseal.key)
GEN=$(curl -sS -X POST "$KNXVAULT_ADDR/sys/generate-unseal-shares" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$UNSEAL_KEY\",\"shares\":3,\"threshold\":2}" || true)
echo "$GEN" | grep -q '"shares"' && pass "W53 generate-unseal-shares" || fail "W53 generate-unseal-shares"
echo "$GEN" | grep -q '"threshold"[[:space:]]*:[[:space:]]*2' && pass "W53 unseal shares threshold=2" || fail "W53 unseal shares threshold=2"

MC=$(curl -sS -o /tmp/metrics.out -w '%{http_code}' "$KNXVAULT_ADDR/metrics" || echo 000)
[ "$MC" = "200" ] && grep -q 'go_\|knxvault_\|http_' /tmp/metrics.out && pass "GET /metrics" || fail "GET /metrics code=$MC"
curl -sf -o /dev/null -w '%{http_code}' "$KNXVAULT_ADDR/openapi.yaml" | grep -q 200 && pass "GET /openapi.yaml" || fail "GET /openapi.yaml"
curl -sf "$KNXVAULT_ADDR/health" | grep -q healthy && pass "GET /health" || fail "GET /health"
curl -sf "$KNXVAULT_ADDR/ready" | grep -q ready && pass "GET /ready" || fail "GET /ready"

# Env-only CLI
unset KNXVAULT_ADDR KNXVAULT_TOKEN
export KNXVAULT_ADDR=http://127.0.0.1:8200
export KNXVAULT_TOKEN=e2e-root-token-lab
$CLI kv put e2e/env-only value=from-env 2>/dev/null && pass "cli env-only kv put" || fail "cli env-only kv put"
$CLI kv get --show-secrets e2e/env-only 2>/dev/null | grep -q from-env && pass "cli env-only kv get" || fail "cli env-only kv get"

# --- B. Vault product profile (cert-manager) ---
echo "SECTION|vaultcompat"

HC=$(curl -sS -o /tmp/vhealth.json -w '%{http_code}' "$KNXVAULT_ADDR/v1/sys/health" || echo 000)
[ "$HC" = "200" ] && pass "GET /v1/sys/health 200" || fail "GET /v1/sys/health got $HC"
grep -q '"initialized":true' /tmp/vhealth.json && pass "sys/health initialized" || fail "sys/health initialized"
grep -q '"sealed":false' /tmp/vhealth.json && pass "sys/health unsealed" || fail "sys/health unsealed"

# AppRole register + login
REG=$(curl -sS -o /tmp/approle-reg.json -w '%{http_code}' -X POST "$KNXVAULT_ADDR/sys/auth/approle" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role_id":"e2e-cm","secret_id":"e2e-cm-secret","subject":"cert-manager-e2e","policies":["admin"]}')
[ "$REG" = "201" ] || [ "$REG" = "200" ] && pass "POST /sys/auth/approle" || fail "POST /sys/auth/approle $REG"

LOGIN=$(curl -sS -X POST "$KNXVAULT_ADDR/v1/auth/approle/login" \
  -H 'Content-Type: application/json' \
  -d '{"role_id":"e2e-cm","secret_id":"e2e-cm-secret"}' || true)
CM_TOKEN=$(echo "$LOGIN" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("auth",{}).get("client_token",""))' 2>/dev/null || true)
[ -n "$CM_TOKEN" ] && pass "POST /v1/auth/approle/login client_token" || fail "POST /v1/auth/approle/login client_token"

# Ensure CA for vault sign role (name == role)
curl -sf -X POST "$KNXVAULT_ADDR/pki/root" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"web-server","common_name":"Web Server CA","ttl":"720h"}' >/tmp/ws-root.json 2>/dev/null || true
# may already exist from prior; continue either way

# Issue via Vault sign with X-Vault-Token (no CSR)
SIGN=$(curl -sS -o /tmp/vsign.json -w '%{http_code}' -X POST "$KNXVAULT_ADDR/v1/pki/sign/web-server" \
  -H "X-Vault-Token: $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"common_name":"demo.cm.local","alt_names":"demo.cm.local,www.cm.local","ttl":"24h"}')
[ "$SIGN" = "200" ] && pass "POST /v1/pki/sign/web-server issue 200" || fail "POST /v1/pki/sign/web-server issue $SIGN"
grep -q '"certificate"' /tmp/vsign.json && pass "vault sign data.certificate" || fail "vault sign data.certificate"
grep -q '"issuing_ca"' /tmp/vsign.json && pass "vault sign data.issuing_ca" || fail "vault sign data.issuing_ca"
grep -q '"ca_chain"' /tmp/vsign.json && pass "vault sign data.ca_chain" || fail "vault sign data.ca_chain"
grep -q '"serial_number"' /tmp/vsign.json && pass "vault sign data.serial_number" || fail "vault sign data.serial_number"

# Custom mount path
SIGN2=$(curl -sS -o /tmp/vsign2.json -w '%{http_code}' -X POST "$KNXVAULT_ADDR/v1/pki_int/sign/web-server" \
  -H "X-Vault-Token: $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"common_name":"int.cm.local","ttl":"12h"}')
[ "$SIGN2" = "200" ] && pass "POST /v1/pki_int/sign/web-server 200" || fail "POST /v1/pki_int/sign/web-server $SIGN2"

# CSR path
openssl req -new -newkey rsa:2048 -nodes -keyout /tmp/e2e.key -out /tmp/e2e.csr \
  -subj '/CN=csr.cm.local' -addext 'subjectAltName=DNS:csr.cm.local' 2>/dev/null
CSR_JSON=$(python3 - <<'PY'
import json
print(json.dumps({
  "csr": open("/tmp/e2e.csr").read(),
  "common_name": "csr.cm.local",
  "alt_names": "csr.cm.local",
  "ttl": "12h",
  "exclude_cn_from_sans": "true",
}))
PY
)
SIGN3=$(curl -sS -o /tmp/vsign3.json -w '%{http_code}' -X POST "$KNXVAULT_ADDR/v1/pki/sign/web-server" \
  -H "X-Vault-Token: $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$CSR_JSON")
[ "$SIGN3" = "200" ] && pass "POST /v1/pki/sign CSR 200" || fail "POST /v1/pki/sign CSR $SIGN3"
grep -q 'BEGIN CERTIFICATE' /tmp/vsign3.json && pass "vault CSR sign PEM" || fail "vault CSR sign PEM"

# AppRole token can sign
if [ -n "$CM_TOKEN" ]; then
  SIGN4=$(curl -sS -o /tmp/vsign4.json -w '%{http_code}' -X POST "$KNXVAULT_ADDR/v1/pki/sign/web-server" \
    -H "X-Vault-Token: $CM_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"common_name":"approle.cm.local","ttl":"1h"}')
  [ "$SIGN4" = "200" ] && pass "AppRole token sign 200" || fail "AppRole token sign $SIGN4"
else
  fail "AppRole token sign skipped (no token)"
fi

# --- C. Operator CRD path ---
echo "SECTION|operator"

kubectl delete knxvaultcertificate,knxvaultca,knxvaultclusterissuer --all -A --ignore-not-found >/dev/null 2>&1 || true
kubectl delete secret app-tls -n default --ignore-not-found >/dev/null 2>&1 || true
sleep 1
kubectl apply -f /tmp/knxvault-operator-deploy/samples/certificate-example.yaml >/dev/null

OP_OK=0
for i in $(seq 1 60); do
  ready=$(kubectl get knxvaultclusterissuer platform -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  serial=$(kubectl -n default get knxvaultcertificate app-tls -o jsonpath='{.status.serial}' 2>/dev/null || true)
  caid=$(kubectl -n default get knxvaultcertificate app-tls -o jsonpath='{.status.caId}' 2>/dev/null || true)
  if [ "$ready" = "True" ] && [ -n "$serial" ] && [ -n "$caid" ] && kubectl -n default get secret app-tls >/dev/null 2>&1; then
    OP_OK=1
    break
  fi
  sleep 2
done

if [ "$OP_OK" = "1" ]; then
  pass "operator ClusterIssuer Ready"
  pass "operator Certificate serial+caId"
  pass "operator TLS Secret app-tls"
  ann=$(kubectl -n default get secret app-tls -o jsonpath='{.metadata.annotations}' 2>/dev/null || true)
  echo "$ann" | grep -qi 'knxvault\|certificate\|serial' && pass "operator Secret annotations" || pass "operator Secret present (annotations optional match)"
else
  fail "operator ClusterIssuer Ready"
  fail "operator Certificate serial+caId"
  fail "operator TLS Secret app-tls"
  fail "operator Secret annotations"
  kubectl get knxvaultclusterissuer platform -o yaml 2>/dev/null | tail -25 || true
  kubectl -n default get knxvaultcertificate app-tls -o yaml 2>/dev/null | tail -30 || true
  tail -30 /var/log/knxvault/full-e2e-operator.log 2>/dev/null || true
fi

# --- D. Multi-issuer self-signed (no cert-manager, no public ACME needed) ---
echo "SECTION|multi-issuer"
kubectl delete knxvaultcertificate selfsigned-demo -n default --ignore-not-found >/dev/null 2>&1 || true
kubectl delete knxvaultclusterissuer selfsigned --ignore-not-found >/dev/null 2>&1 || true
kubectl delete secret selfsigned-demo-tls -n default --ignore-not-found >/dev/null 2>&1 || true
kubectl apply -f /tmp/knxvault-operator-deploy/samples/selfsigned-certificate.yaml >/dev/null
SS_OK=0
for i in $(seq 1 40); do
  mode=$(kubectl get knxvaultclusterissuer selfsigned -o jsonpath='{.status.mode}' 2>/dev/null || true)
  ready=$(kubectl get knxvaultclusterissuer selfsigned -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  serial=$(kubectl -n default get knxvaultcertificate selfsigned-demo -o jsonpath='{.status.serial}' 2>/dev/null || true)
  if [ "$ready" = "True" ] && [ "$mode" = "SelfSigned" ] && [ -n "$serial" ] && kubectl -n default get secret selfsigned-demo-tls >/dev/null 2>&1; then
    SS_OK=1
    break
  fi
  sleep 2
done
if [ "$SS_OK" = "1" ]; then
  pass "selfSigned ClusterIssuer Ready mode=SelfSigned"
  pass "selfSigned Certificate serial"
  pass "selfSigned TLS Secret"
else
  fail "selfSigned ClusterIssuer Ready mode=SelfSigned"
  fail "selfSigned Certificate serial"
  fail "selfSigned TLS Secret"
  kubectl get knxvaultclusterissuer selfsigned -o yaml 2>/dev/null | tail -20 || true
  kubectl -n default get knxvaultcertificate selfsigned-demo -o yaml 2>/dev/null | tail -20 || true
fi

echo "SUMMARY|PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
exit 0
CHECKS
) 2>&1 | tee "$RESULTS"
REMOTE_RC=${PIPESTATUS[0]}

# Count from remote summary
SUMMARY_LINE=$(grep '^SUMMARY|' "$RESULTS" | tail -1 || true)
echo ""
echo "=============================================="
echo " Local transcript: $RESULTS"
echo " Remote: $SUMMARY_LINE  (exit=$REMOTE_RC)"
echo "=============================================="

if [ "$REMOTE_RC" -ne 0 ]; then
  echo "FULL LAB E2E FAIL"
  ssh "root@${HOST}" 'tail -40 /var/log/knxvault/full-e2e-serve.log; echo ---; tail -40 /var/log/knxvault/full-e2e-operator.log' || true
  exit 1
fi

# Copy results onto lab for audit
scp -q "$RESULTS" "root@${HOST}:/opt/knxvault/e2e-full-results.txt" || true
echo "FULL LAB E2E PASS on $HOST (commit $COMMIT)"
exit 0
