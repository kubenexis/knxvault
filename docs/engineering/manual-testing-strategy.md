# Manual Testing Strategy

Structured manual test procedures for validating KNXVault behavior beyond automated unit and integration tests. Use these exercises before BFSI POC sign-off, prospect demonstrations, or after infrastructure changes.

| Field | Value |
|-------|-------|
| **Version** | 1.2 |
| **Last updated** | 2026-07-01 |
| **Audience** | QA, SRE, security engineers, prospect evaluators |
| **Complements** | [`testing.md`](testing.md) (automated), [`../operations/runbooks/raft-failover.md`](../operations/runbooks/raft-failover.md) |

---

## 1. Purpose and scope

Automated tests (`make test`, `make test-integration`, `test/chaos/raft-pod-kill.sh`) prove correctness on a developer machine. **Manual tests** validate production-like scenarios:

- 3-node HA deployment and rolling upgrades
- KV versioning, master key rotation, backup/restore
- Raft failover, membership changes, and network partitions
- Kubernetes and OIDC authentication, RBAC enforcement
- CSI secret delivery, PKI lifecycle, audit SIEM forwarding
- Metrics, health endpoints, and operator observability
- **Subsystem deep-dives** — Dragonboat/Raft, audit chain, storage layer, backup validation, PKI internals, secret engines (KV/database/SSH), K8s webhooks and ESO

Each test defines **procedure**, **pass/fail criteria**, and **evidence to capture**.

---

## 2. Test environment matrix

| Profile | When to use | Minimum topology |
|---------|-------------|------------------|
| **A — Local multi-process** | Fast iteration | 3× `knxvault serve` with distinct `KNXVAULT_RAFT_NODE_ID` |
| **B — Kubernetes StatefulSet** | **Recommended for POC demo** | 3-node Raft per [`deploy/kubernetes.md`](../deploy/kubernetes.md) |
| **C — kind + CSI** | CSI and rotation tests | Profile B + [CSI install](../deploy/csi-install.md) |

### Prerequisites

- [ ] `KNXVAULT_MASTER_KEY` and bootstrap token configured; root token rotated after initial policies
- [ ] `KNXVAULT_RAFT_ENABLED=true`, 3 voting members, PVCs bound
- [ ] `knxvault-cli`, `kubectl`, `curl`, `jq` available
- [ ] Prometheus (optional) scraping `/metrics`
- [ ] Pre-test backup: `knxvault-cli backup create -o pre-poc-backup.json`

### Evidence template

| Field | Example |
|-------|---------|
| Test ID | MT-05 |
| Date / operator | 2026-07-01 / alice |
| Profile | B |
| KNXVault version | `knxvault-cli version` |
| Pass / Fail | Pass |
| Attachments | logs, metrics scrape, audit export |

---

## 3. Test catalog (POC demonstration pack)

| ID | Name | Priority |
|----|------|----------|
| **MT-00** | [Deploy 3-node cluster](#mt-00-deploy-3-node-cluster) | P0 |
| **MT-01** | [Network disruption & Raft recovery](#mt-01-network-disruption--raft-recovery) | P0 |
| **MT-02** | [Secret rotation latency (no pod restart)](#mt-02-secret-rotation-latency-without-workload-restart) | P0 |
| **MT-03** | [KV store, update, version, retrieve](#mt-03-kv-store-update-version-retrieve) | P0 |
| **MT-04** | [Master key rotation without data loss](#mt-04-master-key-rotation-without-data-loss) | P0 |
| **MT-05** | [Leader node kill & automatic failover](#mt-05-leader-node-kill--automatic-failover) | P0 |
| **MT-06** | [Remove and re-add Raft node](#mt-06-remove-and-re-add-raft-node) | P0 |
| **MT-07** | [Backup and restore](#mt-07-backup-and-restore) | P0 |
| **MT-08** | [Kubernetes ServiceAccount authentication](#mt-08-kubernetes-serviceaccount-authentication) | P0 |
| **MT-09** | [OIDC authentication](#mt-09-oidc-authentication) | P0 |
| **MT-10** | [RBAC policy enforcement](#mt-10-rbac-policy-enforcement) | P0 |
| **MT-11** | [Audit export & SIEM forwarding](#mt-11-audit-export--siem-forwarding) | P0 |
| **MT-12** | [Secrets Store CSI Driver integration](#mt-12-secrets-store-csi-driver-integration) | P0 |
| **MT-13** | [Certificate issuance and revocation](#mt-13-certificate-issuance-and-revocation) | P0 |
| **MT-14** | [Prometheus metrics & health endpoints](#mt-14-prometheus-metrics--health-endpoints) | P0 |
| **MT-15** | [Rolling upgrade without downtime](#mt-15-rolling-upgrade-without-downtime) | P0 |

---

## MT-00: Deploy 3-node cluster

### Objective

Deploy a production-like 3-node KNXVault Raft cluster and confirm quorum health.

### Procedure

```bash
# Build and push image (adjust registry/tag)
make docker-build
# Update deployments/k8s/statefulset.yaml image:

kubectl apply -f deployments/k8s/namespace.yaml
kubectl apply -f deployments/k8s/serviceaccount.yaml
kubectl apply -f deployments/k8s/role.yaml
kubectl apply -f deployments/k8s/rolebinding.yaml
kubectl apply -f deployments/k8s/configmap.yaml
kubectl apply -f deployments/k8s/secret.yaml
kubectl apply -f deployments/k8s/service-raft.yaml
kubectl apply -f deployments/k8s/statefulset.yaml
kubectl apply -f deployments/k8s/service.yaml
kubectl apply -f deployments/k8s/pdb.yaml
kubectl apply -f deployments/k8s/networkpolicy.yaml   # optional

kubectl -n knxvault wait --for=condition=ready pod -l app.kubernetes.io/name=knxvault --timeout=600s
```

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<bootstrap-token>

knxvault-cli doctor
knxvault-cli health
curl -s "$KNXVAULT_ADDR/ready" | jq .
```

Verify all three pods: `raft_ready: true`, exactly one reports `leader: true` in `/ready` (or via metrics).

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | 3 pods Running; PVCs Bound |
| 2 | `/ready` returns 200 on all replicas |
| 3 | Exactly one `knxvault_raft_leader = 1` across cluster |
| 4 | `knxvault-cli doctor` passes |

---

## MT-01: Network disruption & Raft recovery

### Objective

Store secrets, break network connectivity between Raft peers, observe recovery (no auto-seal), and verify data after heal.

### Expected baseline

| Behavior | KNXVault |
|----------|----------|
| Auto-seal on network loss | **No** — seal is operator-initiated only |
| Minority partition writes | Rejected (no quorum) |
| Majority partition writes | Continue |
| Recovery after heal | Automatic Raft catch-up |

### Procedure (summary)

1. **Baseline** — `kv put mt01/secret-a`, capture leader and `knxvault_raft_commit_index` on all nodes.
2. **Partition** — Isolate one replica (NetworkPolicy deny-all on `knxvault-2`, or block Raft port 63001).
3. **Observe** (15–30 min) — Majority accepts writes; minority does not; vault stays **unsealed**.
4. **Heal** — Remove isolation policy.
5. **Verify** — All pods ready; secrets intact; commit index converged.

Detailed steps: see [MT-01 phases](#mt-01-detail-network-partition) in appendix below, or original partition tables in prior revisions — use NetworkPolicy example:

```yaml
# mt01-isolate-knxvault-2.yaml — deny all traffic to/from knxvault-2
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mt01-isolate-knxvault-2
  namespace: knxvault
spec:
  podSelector:
    matchLabels:
      statefulset.kubernetes.io/pod-name: knxvault-2
  policyTypes: [Ingress, Egress]
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | No auto-seal during partition |
| 2 | Majority writes succeed; minority writes fail |
| 3 | Full recovery within 5 min of heal; data intact |

---

## MT-02: Secret rotation latency (without workload restart)

### Objective

Measure time from KV rotation to updated secret visible in a running pod **without** restart.

### Procedure

1. Install CSI with `enableSecretRotation=true` ([`csi-install.md`](../deploy/csi-install.md)).
2. Deploy `SecretProviderClass` with `rotationPollInterval: 30s` and a log-loop pod (see [MT-02 setup](#mt-02-detail-csi-rotation-pod) in appendix).
3. `kv put mt02/app-cred value=version-1` → confirm in pod logs.
4. `kv put mt02/app-cred value=version-2` at **T_rotate**.
5. Record **T_visible** when logs show `version-2`. Latency = `T_visible - T_rotate`.

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | New value visible without pod restart |
| 2 | Median latency ≤ `rotationPollInterval` + 15s |

---

## MT-03: KV store, update, version, retrieve

### Objective

Demonstrate KVv2 lifecycle: create, update (new version), read specific version, metadata, list, soft delete, destroy.

### Procedure

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

# Create v1
curl -s -X POST "$KNXVAULT_ADDR/secrets/kv/demo/app/config" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"password":"v1-secret","user":"app"}}' | jq .

# Update → v2
curl -s -X POST "$KNXVAULT_ADDR/secrets/kv/demo/app/config" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"password":"v2-secret","user":"app"}}' | jq .

# Read latest
curl -s "$KNXVAULT_ADDR/secrets/kv/demo/app/config" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .

# Read version 1
curl -s "$KNXVAULT_ADDR/secrets/kv/demo/app/config?version=1" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .

# List versions
curl -s "$KNXVAULT_ADDR/secrets/kv/demo/app/config/versions" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .

# Metadata
curl -s "$KNXVAULT_ADDR/secrets/kv/demo/app/config/metadata" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .

# CAS write (optional)
curl -s -X POST "$KNXVAULT_ADDR/secrets/kv/demo/app/config" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"password":"v3-cas"},"options":{"cas_version":2}}' | jq .

# List paths under prefix
curl -s "$KNXVAULT_ADDR/secrets/kv/demo?list=true&prefix=demo" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .

# Soft delete (latest)
curl -s -X DELETE "$KNXVAULT_ADDR/secrets/kv/demo/app/config" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" -w "\n%{http_code}\n"

# Destroy version 1 permanently
curl -s -X DELETE "$KNXVAULT_ADDR/secrets/kv/demo/app/config?version=1" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" -w "\n%{http_code}\n"
```

CLI equivalents: `knxvault-cli kv put`, `knxvault-cli kv get --show-secrets`.

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Version increments on each PUT; v1 readable after v2 created |
| 2 | `?version=1` returns v1 payload; latest returns v2 |
| 3 | `/versions` lists all versions with `destroyed` flags |
| 4 | CAS with wrong version rejected |
| 5 | Destroy removes version; audit entries for read/write/delete |

---

## MT-04: Master key rotation without data loss

### Objective

Rotate the envelope master key and verify all existing secrets remain readable.

### Procedure

```bash
# 1. Seed secrets before rotation
knxvault-cli kv put mt04/before-rotate value=keep-me
knxvault-cli kv get mt04/before-rotate --show-secrets

# 2. Record active key version (from metrics or API if exposed)
curl -s "$KNXVAULT_ADDR/metrics" | grep knxvault_master_key_version || true

# 3. Generate new 32-byte key
NEW_KEY=$(openssl rand -base64 32)
knxvault-cli sys rotate-master-key --key "$NEW_KEY"
# Or: curl -X POST $KNXVAULT_ADDR/sys/rotate-master-key -d '{"key":"..."}'

# 4. Wait for leader background re-encrypt job (check leader pod logs)
kubectl -n knxvault logs knxvault-<leader> | grep -i reencrypt || true
sleep 30

# 5. Read pre-rotation secret on ALL replicas (via port-forward each pod)
knxvault-cli kv get mt04/before-rotate --show-secrets

# 6. Write and read new secret after rotation
knxvault-cli kv put mt04/after-rotate value=post-rotation
knxvault-cli kv get mt04/after-rotate --show-secrets

# 7. Backup after rotation
knxvault-cli backup create -o post-rotate-backup.json
```

Store `NEW_KEY` securely; old key may still decrypt legacy DEKs until re-encrypt completes.

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | `rotate-master-key` succeeds |
| 2 | Secrets written **before** rotation readable after rotation |
| 3 | New writes succeed on all cluster members |
| 4 | Backup/restore of rotated state succeeds (cross-check with MT-07) |
| 5 | No plaintext secrets in logs |

---

## MT-05: Leader node kill & automatic failover

### Objective

Kill the current Raft leader and verify automatic election, continued availability, and data integrity.

### Procedure

```bash
# Identify leader
LEADER=$(kubectl -n knxvault get pods -l app.kubernetes.io/name=knxvault -o json \
  | jq -r '.items[] | select(.metadata.annotations.leader // "")' )  # or use metrics
# Simpler: check /ready on each pod
for i in 0 1 2; do
  echo -n "knxvault-$i: "
  kubectl -n knxvault exec knxvault-$i -- wget -qO- http://localhost:8200/ready 2>/dev/null | jq -c '{leader,raft_ready}'
done

# Background write loop (separate terminal)
while true; do
  knxvault-cli kv put mt05/failover-test value=$(date +%s) 2>&1 | tail -1
  sleep 2
done

# Kill leader pod
kubectl -n knxvault delete pod <leader-pod-name> --wait=false

# Observe failover window (typically 10–30s)
watch -n2 'curl -s $KNXVAULT_ADDR/ready | jq .'

# After replacement pod Ready:
for i in 0 1 2; do
  kubectl -n knxvault exec knxvault-$i -- wget -qO- http://localhost:8200/metrics 2>/dev/null \
    | grep knxvault_raft_leader
done

knxvault-cli kv get mt05/failover-test --show-secrets
```

Alternative: `./test/chaos/raft-pod-kill.sh`

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | New leader elected within 60s |
| 2 | Writes resume after brief gap (document max gap) |
| 3 | No data corruption; latest KV value readable |
| 4 | Exactly one leader after recovery |

---

## MT-06: Remove and re-add Raft node

### Objective

Remove a voting member and add it back without cluster corruption.

### Procedure

> Use a **replacement** scenario on a 3-node cluster: remove node ID **3**, replace `knxvault-2` pod with fresh Raft data, rejoin.

```bash
# 1. Confirm quorum
curl -s "$KNXVAULT_ADDR/ready" | jq .

# 2. Remove node 3 (adjust ID to match your pod knxvault-2 → node 3)
curl -s -X POST "$KNXVAULT_ADDR/sys/raft/remove-node" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"node_id":3}'

# 3. Scale down or delete knxvault-2; wipe its PVC OR use fresh empty data dir
kubectl -n knxvault delete pod knxvault-2 --wait=true
# Optional: delete PVC for knxvault-2 if testing full replacement (destructive)

# 4. Re-create pod with KNXVAULT_RAFT_JOIN=true and updated member list in ConfigMap
#    See docs/operations/runbooks/scaling.md

# 5. Add node back
curl -s -X POST "$KNXVAULT_ADDR/sys/raft/add-node" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"node_id":3,"address":"knxvault-2.knxvault-headless.knxvault.svc.cluster.local:63001"}'

# 6. Verify write/read on all members
knxvault-cli kv put mt06/membership value=rejoined
knxvault-cli kv get mt06/membership --show-secrets
```

CLI: `knxvault-cli sys raft-remove-node`, `knxvault-cli sys raft-add-node`.

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | `remove-node` succeeds with quorum intact |
| 2 | Cluster remains writable with 2/3 during removal |
| 3 | `add-node` succeeds; new member catches up |
| 4 | 3-node quorum restored; KV round-trip on all pods |

---

## MT-07: Backup and restore

### Objective

Create an encrypted backup and restore vault state without data loss.

### Procedure

```bash
# Seed data
knxvault-cli kv put mt07/restore-test value=backup-me
knxvault-cli sys policies put mt07-reader -f - <<'EOF'
{"effect":"allow","resources":["secrets/kv/mt07/*"],"actions":["read"]}
EOF

# Backup
knxvault-cli backup create -o mt07-backup.json

# Optional: destructive test on non-prod — deploy fresh single-node or staging namespace
# Restore (requires same KNXVAULT_MASTER_KEY)
knxvault-cli backup restore -f mt07-backup.json

# Verify
knxvault-cli kv get mt07/restore-test --show-secrets
curl -s -X POST "$KNXVAULT_ADDR/audit/verify" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @<(curl -s "$KNXVAULT_ADDR/audit/export" -H "Authorization: Bearer $KNXVAULT_TOKEN")
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Backup file created; non-empty; encrypted payload |
| 2 | Restore completes without error |
| 3 | KV, policies, and audit chain verify post-restore |
| 4 | `ValidateSnapshot` path rejects tampered backup (optional negative test) |

---

## MT-08: Kubernetes ServiceAccount authentication

### Objective

Authenticate using a pod ServiceAccount JWT (TokenReview) and obtain a scoped client token.

### Procedure

```bash
# 1. Create SA and role binding in KNXVault
curl -s -X PUT "$KNXVAULT_ADDR/sys/roles/demo-app" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "policies": ["secrets-reader"],
    "bound_service_account_names": ["demo-app"],
    "bound_service_account_namespaces": ["default"]
  }'

# 2. Deploy test pod with SA demo-app
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: demo-app
  namespace: default
---
apiVersion: v1
kind: Pod
metadata:
  name: mt08-auth-test
  namespace: default
spec:
  serviceAccountName: demo-app
  containers:
    - name: shell
      image: curlimages/curl:8.5.0
      command: ["sleep", "3600"]
EOF

# 3. Login from pod
kubectl exec mt08-auth-test -- sh -c '
  JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  curl -s -X POST "$KNXVAULT_ADDR/auth/kubernetes" \
    -H "Content-Type: application/json" \
    -d "{\"role\":\"demo-app\",\"jwt\":\"$JWT\"}"
'

# 4. Use returned client_token to read allowed path; verify 403 on admin path
```

Requires KNXVault in-cluster with TokenReview RBAC (`KNXVAULT_K8S_AUTH_INSECURE=false`).

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Matching SA → `200` + client token |
| 2 | Wrong SA or namespace → `403` |
| 3 | Token can read secrets per policy; denied on `sys/*` |
| 4 | Audit records login (when W43-01 shipped) or appears in export |

---

## MT-09: OIDC authentication

### Objective

Authenticate via `POST /auth/oidc/:role` using a corporate/IdP JWT.

### Procedure

```bash
# 1. Configure role with OIDC (API: backlog W43-06 — use domain/Raft or API when available)
curl -s -X PUT "$KNXVAULT_ADDR/sys/roles/oidc-demo" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "policies": ["secrets-reader"],
    "auth_method": "oidc",
    "oidc": {
      "issuer": "https://idp.example.com/realms/demo",
      "audience": "knxvault",
      "jwks_url": "https://idp.example.com/realms/demo/protocol/openid-connect/certs",
      "max_ttl_seconds": 3600
    }
  }'
# If oidc block not accepted by API yet, configure via documented workaround / backlog W43-06.

# 2. Obtain IdP JWT (browser flow, client credentials, or test IdP)
export OIDC_JWT=<idp-access-token>

# 3. Login
curl -s -X POST "$KNXVAULT_ADDR/auth/oidc/oidc-demo" \
  -H 'Content-Type: application/json' \
  -d "{\"jwt\":\"$OIDC_JWT\"}" | jq .

# 4. Use client_token for KV read
export KNXVAULT_TOKEN=<client_token_from_response>
knxvault-cli kv get demo/oidc-test --show-secrets
```

Negative tests: expired JWT, wrong `aud`, wrong `iss` → `401`/`403`.

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Valid OIDC JWT mints client token |
| 2 | Invalid/expired/wrong-audience JWT rejected |
| 3 | Token TTL ≤ role `max_ttl_seconds` |
| 4 | NHI record created (`GET /sys/machine-identities`) |

---

## MT-10: RBAC policy enforcement

### Objective

Demonstrate allow and deny policies; verify least-privilege enforcement.

### Procedure

```bash
# Reader policy
curl -s -X PUT "$KNXVAULT_ADDR/sys/policies/mt10-reader" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"effect":"allow","resources":["secrets/kv/mt10/*"],"actions":["read"]}'

# Deny policy (explicit deny — backlog W41-03 for cross-policy precedence tests)
curl -s -X PUT "$KNXVAULT_ADDR/sys/policies/mt10-deny-admin" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"effect":"deny","resources":["sys/*"],"actions":["*"]}'

# Role + token
curl -s -X PUT "$KNXVAULT_ADDR/sys/roles/mt10-tester" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"policies":["mt10-reader","mt10-deny-admin"]}'

curl -s -X POST "$KNXVAULT_ADDR/auth/token/create" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role":"mt10-tester","ttl":"1h"}' | jq .

export SCOPED_TOKEN=<client_token>

# Allowed
curl -s -o /dev/null -w "%{http_code}" "$KNXVAULT_ADDR/secrets/kv/mt10/app" \
  -H "Authorization: Bearer $SCOPED_TOKEN"
# Expect 200 or 404 (not 403)

# Denied
curl -s -o /dev/null -w "%{http_code}" -X POST "$KNXVAULT_ADDR/sys/policies" \
  -H "Authorization: Bearer $SCOPED_TOKEN"
# Expect 403

# Denied write
curl -s -o /dev/null -w "%{http_code}" -X POST "$KNXVAULT_ADDR/secrets/kv/mt10/app" \
  -H "Authorization: Bearer $SCOPED_TOKEN" -H 'Content-Type: application/json' \
  -d '{"data":{"x":"1"}}'
# Expect 403
```

> **Note:** Path-level ACLs (e.g. `secrets/kv/team-a/*` only) require **W41-01**. Current enforcement is route-coarse (`secrets/kv` + action).

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Reader token can GET KV |
| 2 | Reader token cannot POST KV or sys admin APIs |
| 3 | Deny policy blocks `sys/*` even with other allows |
| 4 | `403` responses include request ID |

---

## MT-11: Audit export & SIEM forwarding

### Objective

Export tamper-evident audit logs and forward to a SIEM-compatible HTTP sink.

### Procedure

```bash
# 1. Configure signing key and forward URL on KNXVault deployment
# KNXVAULT_AUDIT_SIGNING_KEY=<random>
# KNXVAULT_AUDIT_FORWARD_URL=http://siem-collector:8080/audit

# 2. Generate auditable events (KV read/write, auth, PKI)
knxvault-cli kv put mt11/audited value=test
knxvault-cli kv get mt11/audited --show-secrets

# 3. Export bundle
curl -s "$KNXVAULT_ADDR/audit/export" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq . > mt11-audit-export.json

# 4. Verify hash chain + signatures
curl -s -X POST "$KNXVAULT_ADDR/audit/verify" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @mt11-audit-export.json | jq .

# 5. Confirm SIEM sink received JSON lines (Splunk HEC, Loki, or mock server)
# Each POST body matches audit.Entry schema per docs/observability/audit-forwarding.md
```

SIEM compatibility: JSON over HTTP (Splunk HEC, Elastic ingest, Loki via Alloy/Promtail).

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Export returns entries with `hash` and `signature` |
| 2 | `audit/verify` returns success on unmodified export |
| 3 | Tampered entry fails verify |
| 4 | Forwarder receives events within 5s of API calls |
| 5 | Entries include `actor`, `action`, `resource`, `status`, `timestamp` |

---

## MT-12: Secrets Store CSI Driver integration

### Objective

Mount KV secrets into a pod via the KNXVault CSI provider without static vault tokens in the workload.

### Procedure

```bash
# Install driver + provider (Profile C)
helm install csi secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system --set syncSecret.enabled=true --set enableSecretRotation=true
kubectl apply -f deployments/csi/rbac.yaml
kubectl apply -f deployments/csi/k8s-provider.yaml
kubectl apply -f deployments/csi/secretproviderclass-example.yaml
kubectl apply -f deployments/csi/pod-example.yaml

# Verify mount
kubectl wait --for=condition=ready pod/knxvault-csi-demo --timeout=120s
kubectl exec knxvault-csi-demo -- cat /mnt/secrets/db.env

# Provider logs — TokenReview per mount
kubectl logs -n knxvault -l app.kubernetes.io/name=knxvault-csi-provider --tail=50

# Optional: scripts/test-csi-kind.sh for automated smoke
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Pod reaches Ready; file exists at mount path |
| 2 | Content matches KV secret in vault |
| 3 | Wrong SA → mount fails (auth test) |
| 4 | `csi.mount` audit recorded when mount-audit enabled |

---

## MT-13: Certificate issuance and revocation

### Objective

Issue a leaf certificate from KNXVault PKI and revoke it; verify CRL reflects revocation.

### Procedure

```bash
# 1. Create root CA (if not exists)
curl -s -X POST "$KNXVAULT_ADDR/pki/root" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mt13-root","common_name":"MT13 Root CA","ttl":"8760h"}' | jq .

export CA_ID=<ca_id>

# 2. Issue leaf cert
curl -s -X POST "$KNXVAULT_ADDR/pki/issue" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{
    \"ca_id\": \"$CA_ID\",
    \"common_name\": \"mt13.example.com\",
    \"dns_sans\": [\"mt13.example.com\"],
    \"ttl\": \"24h\"
  }" | jq . > mt13-cert.json

SERIAL=$(jq -r .serial mt13-cert.json)

# 3. Fetch CRL — cert present as good (not revoked)
curl -s "$KNXVAULT_ADDR/pki/crl/$CA_ID" -H "Authorization: Bearer $KNXVAULT_TOKEN" | openssl crl -inform PEM -noout -text | grep -F "$SERIAL" || echo "not yet revoked"

# 4. Revoke
curl -s -X POST "$KNXVAULT_ADDR/pki/revoke" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"ca_id\":\"$CA_ID\",\"serial\":\"$SERIAL\",\"reason\":\"test\"}"

# 5. CRL shows revoked serial; OCSP optional
curl -s "$KNXVAULT_ADDR/pki/crl/$CA_ID" -H "Authorization: Bearer $KNXVAULT_TOKEN" | openssl crl -inform PEM -noout -text | grep -F "$SERIAL"
```

CLI: `knxvault-cli pki` subcommands where available.

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Issue returns `cert_pem`, `key_pem`, `serial` |
| 2 | Revoke succeeds |
| 3 | CRL includes revoked serial |
| 4 | Audit entries for issue and revoke |

---

## MT-14: Prometheus metrics & health endpoints

### Objective

Demonstrate observability endpoints for monitoring integration.

### Procedure

```bash
# Liveness
curl -s "$KNXVAULT_ADDR/health" | jq .

# Readiness (per pod)
for i in 0 1 2; do
  echo "=== knxvault-$i ==="
  kubectl -n knxvault exec knxvault-$i -- wget -qO- http://localhost:8200/ready
done

# Metrics
curl -s "$KNXVAULT_ADDR/metrics" | grep -E '^knxvault_' | head -40

# Key series
curl -s "$KNXVAULT_ADDR/metrics" | grep -E \
  'knxvault_raft_leader|knxvault_raft_commit_index|knxvault_http_request|knxvault_active_leases'

# Optional: apply alert rules
kubectl apply -f deployments/prometheus/knxvault-alerts.yaml
```

See [`docs/metrics.md`](../metrics.md) and Grafana dashboard `deployments/grafana/knxvault-overview.json`.

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | `/health` → 200 `ok` |
| 2 | `/ready` → 200 with `raft_ready` and `leader` on quorum members |
| 3 | `/metrics` exposes Raft, HTTP, lease, and build info metrics |
| 4 | Metrics update after failover (leader gauge moves) |

---

## MT-15: Rolling upgrade without downtime

### Objective

Upgrade KNXVault image across a 3-node StatefulSet one replica at a time with no prolonged write outage.

### Procedure

```bash
# 0. Pre-upgrade backup
knxvault-cli backup create -o pre-upgrade-backup.json

# 1. Record baseline
curl -s "$KNXVAULT_ADDR/ready" | jq .
BASE_INDEX=$(curl -s "$KNXVAULT_ADDR/metrics" | grep knxvault_raft_commit_index | tail -1)

# 2. Background write loop
while true; do knxvault-cli kv put mt15/upgrade value=$(date +%s); sleep 1; done &
LOOP_PID=$!

# 3. Rolling upgrade — one pod at a time (newest ordinal first is common)
NEW_IMAGE=registry.example.com/knxvault:<new-tag>
kubectl -n knxvault set image statefulset/knxvault knxvault="$NEW_IMAGE"

for i in 2 1 0; do
  echo "Upgrading knxvault-$i"
  kubectl -n knxvault delete pod knxvault-$i --wait=true
  kubectl -n knxvault wait --for=condition=ready pod/knxvault-$i --timeout=300s
  curl -s "$KNXVAULT_ADDR/ready" | jq .
  sleep 10
done

kill $LOOP_PID

# 4. Post-upgrade smoke
knxvault-cli doctor
knxvault-cli kv put mt15/post-upgrade value=ok
knxvault-cli kv get mt15/post-upgrade --show-secrets
curl -s -X POST "$KNXVAULT_ADDR/pki/issue" ...  # optional PKI smoke
```

Document any write failures during pod restarts (expect brief blip if leader restarted; quorum must hold).

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | ≥2 nodes healthy throughout; quorum never lost |
| 2 | Write loop recovers automatically (document max error window) |
| 3 | All pods on new image version (`knxvault_build_info`) |
| 4 | KV and PKI smoke tests pass post-upgrade |
| 5 | Pre-upgrade backup restorable (optional MT-07 cross-check) |

---

## 4. Test catalog (subsystem deep-dives)

Engineering-focused tests that exercise internal components beyond the prospect demo pack. Run on **Profile B** (or **A** for Raft-only tests) after **MT-00** establishes a healthy cluster.

### 4.1 Dragonboat / Raft

| ID | Name | Priority |
|----|------|----------|
| **MT-16** | [Raft quorum write enforcement](#mt-16-raft-quorum-write-enforcement) | P1 |
| **MT-17** | [Cold restart & snapshot catch-up](#mt-17-cold-restart--snapshot-catch-up) | P1 |
| **MT-18** | [Leader-only admin & background jobs](#mt-18-leader-only-admin--background-jobs) | P1 |

### 4.2 Audit subsystem

| ID | Name | Priority |
|----|------|----------|
| **MT-19** | [Audit hash chain integrity](#mt-19-audit-hash-chain-integrity) | P1 |
| **MT-20** | [Audit signing & forwarder delivery](#mt-20-audit-signing--forwarder-delivery) | P1 |

### 4.3 Storage / repository layer

| ID | Name | Priority |
|----|------|----------|
| **MT-21** | [Encrypt-before-replicate evidence](#mt-21-encrypt-before-replicate-evidence) | P1 |
| **MT-22** | [Seal / unseal write gate](#mt-22-seal--unseal-write-gate) | P1 |

### 4.4 Backup and restore (advanced)

| ID | Name | Priority |
|----|------|----------|
| **MT-23** | [Atomic backup with audit history](#mt-23-atomic-backup-with-audit-history) | P1 |
| **MT-24** | [Restore validation & negative cases](#mt-24-restore-validation--negative-cases) | P1 |

### 4.5 PKI internals

| ID | Name | Priority |
|----|------|----------|
| **MT-25** | [Intermediate CA chain & leaf lifecycle](#mt-25-intermediate-ca-chain--leaf-lifecycle) | P1 |
| **MT-26** | [CA import, rotate, export](#mt-26-ca-import-rotate-export) | P1 |

### 4.6 Secret engines

| ID | Name | Priority |
|----|------|----------|
| **MT-27** | [Database dynamic credentials & leases](#mt-27-database-dynamic-credentials--leases) | P1 |
| **MT-28** | [SSH signed user certificates](#mt-28-ssh-signed-user-certificates) | P1 |
| **MT-29** | [Orchestrated rotation job](#mt-29-orchestrated-rotation-job) | P1 |

### 4.7 Kubernetes controllers / webhooks

| ID | Name | Priority |
|----|------|----------|
| **MT-30** | [Mutating admission webhook injection](#mt-30-mutating-admission-webhook-injection) | P1 |
| **MT-31** | [External Secrets Operator webhook sync](#mt-31-external-secrets-operator-webhook-sync) | P1 |
| **MT-32** | [cert-manager Vault issuer sign flow](#mt-32-cert-manager-vault-issuer-sign-flow) | P2 |

---

## MT-16: Raft quorum write enforcement

### Objective

Confirm Dragonboat rejects writes when quorum is lost and that committed entries replicate to all followers.

### Procedure

```bash
# 1. Baseline — write on healthy cluster
knxvault-cli kv put mt16/quorum value=baseline
BASE_INDEX=$(curl -s "$KNXVAULT_ADDR/metrics" | awk '/knxvault_raft_commit_index/{print $2; exit}')

# 2. Isolate minority (one follower) — see MT-01 NetworkPolicy
kubectl apply -f mt01-isolate-knxvault-2.yaml

# 3. Writes via Service (majority path) should succeed
knxvault-cli kv put mt16/quorum value=majority-ok

# 4. Port-forward to isolated follower; read should eventually show majority write OR stay stale until heal
kubectl -n knxvault port-forward knxvault-2 8202:8200 &
curl -s http://localhost:8202/ready | jq '{raft_ready,leader}'

# 5. Isolate leader + one follower (lose quorum) — writes must fail
#    Apply deny policies to 2 of 3 pods; attempt write:
knxvault-cli kv put mt16/quorum value=should-fail
# Expect non-2xx or timeout

# 6. Heal; verify commit index >= BASE_INDEX on all pods
kubectl delete -f mt01-isolate-knxvault-2.yaml
for i in 0 1 2; do
  kubectl -n knxvault exec knxvault-$i -- wget -qO- http://localhost:8200/metrics 2>/dev/null \
    | grep knxvault_raft_commit_index
done
knxvault-cli kv get mt16/quorum --show-secrets
```

See [`docs/storage/dragonboat.md`](../storage/dragonboat.md) and [`docs/storage/raft-ha-and-recovery.md`](../storage/raft-ha-and-recovery.md).

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Majority partition accepts `SyncPropose` writes |
| 2 | Quorum loss rejects writes (no silent data loss) |
| 3 | After heal, all replicas converge on same commit index |
| 4 | Isolated follower `raft_ready` may be false until catch-up |

---

## MT-17: Cold restart & snapshot catch-up

### Objective

Verify a stopped Raft member recovers from on-disk Dragonboat snapshots without manual `snapshot.import`.

### Procedure

```bash
# 1. Seed state
knxvault-cli kv put mt17/snapshot value=pre-restart-$(date +%s)
PRE_INDEX=$(curl -s "$KNXVAULT_ADDR/metrics" | awk '/knxvault_raft_commit_index/{print $2; exit}')

# 2. Trigger on-disk snapshot via backup API
curl -s -X POST "$KNXVAULT_ADDR/sys/backup" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"include_audit":false}' | jq -r '.data' | head -c 20

# 3. Gracefully delete follower pod (PVC retained)
kubectl -n knxvault delete pod knxvault-1 --wait=true
kubectl -n knxvault wait --for=condition=ready pod/knxvault-1 --timeout=300s

# 4. Verify catch-up without operator restore
kubectl -n knxvault logs knxvault-1 --tail=80 | grep -iE 'snapshot|recover|catch' || true
curl -s http://localhost:8200/ready  # via port-forward to knxvault-1 if needed
knxvault-cli kv get mt17/snapshot --show-secrets

POST_INDEX=$(kubectl -n knxvault exec knxvault-1 -- wget -qO- http://localhost:8200/metrics 2>/dev/null \
  | awk '/knxvault_raft_commit_index/{print $2; exit}')
test "$POST_INDEX" -ge "$PRE_INDEX"
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Restarted pod reaches `raft_ready: true` without manual import |
| 2 | Commit index on restarted member ≥ pre-restart cluster index |
| 3 | KV data readable on restarted member |
| 4 | No split-brain (exactly one leader) |

---

## MT-18: Leader-only admin & background jobs

### Objective

Validate Raft admin APIs and background work execute only on the elected leader.

### Procedure

```bash
# 1. Identify leader pod
for i in 0 1 2; do
  echo -n "knxvault-$i: "
  kubectl -n knxvault exec knxvault-$i -- wget -qO- http://localhost:8200/ready 2>/dev/null | jq -c .leader
done

# 2. Port-forward to a known follower; attempt add-node (should fail or redirect)
FOLLOWER=knxvault-0  # adjust
kubectl -n knxvault port-forward $FOLLOWER 8210:8200 &
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8210/sys/raft/add-node \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"node_id":99,"address":"test:63001"}'
# Expect 4xx/5xx or explicit not-leader error

# 3. Same request via Service (routes to leader) — expect structured rejection for invalid node, not "not leader"
curl -s -X POST "$KNXVAULT_ADDR/sys/raft/add-node" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"node_id":99,"address":"test:63001"}' | jq .

# 4. Master key rotation — re-encrypt logs appear only on leader
knxvault-cli sys rotate-master-key --key "$(openssl rand -base64 32)"
sleep 5
for i in 0 1 2; do
  echo "=== knxvault-$i reencrypt logs ==="
  kubectl -n knxvault logs knxvault-$i --tail=30 | grep -i reencrypt || echo "(none)"
done

# 5. Metrics: knxvault_raft_leader=1 on exactly one pod
for i in 0 1 2; do
  kubectl -n knxvault exec knxvault-$i -- wget -qO- http://localhost:8200/metrics 2>/dev/null \
    | grep knxvault_raft_leader
done
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | `add-node` / `remove-node` succeed only when directed at leader |
| 2 | Background re-encrypt activity logged on leader only |
| 3 | `knxvault_raft_leader` gauge is `1` on one replica, `0` on others |
| 4 | Follower direct admin calls do not mutate cluster state |

---

## MT-19: Audit hash chain integrity

### Objective

Prove the audit repository maintains a tamper-evident hash chain across Raft replication.

### Procedure

```bash
# 1. Generate diverse audit events
knxvault-cli kv put mt19/chain value=one
knxvault-cli kv get mt19/chain --show-secrets
curl -s -X POST "$KNXVAULT_ADDR/sys/policies/mt19-test" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"effect":"allow","resources":["secrets/kv/mt19/*"],"actions":["read"]}'

# 2. Export with pagination
curl -s "$KNXVAULT_ADDR/audit/export?limit=50" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq '{count:(.entries|length), head_hash, signature}' \
  > mt19-export-a.json

# 3. Verify intact export
curl -s -X POST "$KNXVAULT_ADDR/audit/verify" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @mt19-export-a.json | jq .

# 4. Tamper test — flip one entry hash
jq '(.entries[0].hash)="deadbeef"' mt19-export-a.json > mt19-export-tampered.json
curl -s -X POST "$KNXVAULT_ADDR/audit/verify" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @mt19-export-tampered.json | jq .

# 5. Filter export
curl -s "$KNXVAULT_ADDR/audit/export?since=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq '.entries | map(select(.resource|test("mt19")))'
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Each entry has monotonic `id` and non-empty `hash` |
| 2 | `audit/verify` succeeds on unmodified export |
| 3 | Tampered entry or hash fails verification |
| 4 | `head_hash` matches tip of exported chain |
| 5 | Audit entries replicate — export identical from any cluster member |

---

## MT-20: Audit signing & forwarder delivery

### Objective

Validate optional HMAC signing of export head and asynchronous HTTP forwarding to a SIEM sink.

### Procedure

```bash
# 1. Deploy mock SIEM sink (Profile B)
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: mt20-siem-mock
  namespace: knxvault
spec:
  containers:
    - name: netcat
      image: busybox:1.36
      command: ["sh", "-c", "while true; do nc -l -p 8080 -e wc -c; done"]
EOF

# 2. Configure KNXVault (ConfigMap patch or env):
# KNXVAULT_AUDIT_SIGNING_KEY=<random-32b>
# KNXVAULT_AUDIT_FORWARD_URL=http://mt20-siem-mock.knxvault.svc:8080/audit
# Rolling restart one pod at a time to pick up config.

# 3. Generate events
knxvault-cli kv put mt20/forward value=siem-test

# 4. Export — expect signature + signed_at when signing key set
curl -s "$KNXVAULT_ADDR/audit/export?limit=10" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq '{signature, signed_at, head_hash}'

# 5. Verify with signature fields from export response body
curl -s -X POST "$KNXVAULT_ADDR/audit/verify" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$(curl -s "$KNXVAULT_ADDR/audit/export?limit=5" -H "Authorization: Bearer $KNXVAULT_TOKEN")" | jq .

# 6. Confirm forwarder received JSON (check mock pod logs or tcpdump sidecar)
kubectl -n knxvault logs mt20-siem-mock --tail=20
```

See [`docs/observability/audit-forwarding.md`](../observability/audit-forwarding.md).

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Export includes `signature` and `signed_at` when signing key configured |
| 2 | `audit/verify` validates head signature |
| 3 | Forwarder receives POST per auditable API call (within 5s) |
| 4 | API requests succeed even if forwarder is down (async, non-blocking) |
| 5 | Forwarded payload matches `audit.Entry` schema |

---

## MT-21: Encrypt-before-replicate evidence

### Objective

Confirm secret plaintext never appears in Raft on-disk artifacts (ADR-0004 invariant).

### Procedure

```bash
# 1. Write a distinctive canary value
CANARY="mt21-plaintext-must-not-appear-$(openssl rand -hex 8)"
knxvault-cli kv put mt21/canary value="$CANARY"

# 2. Wait for Raft commit
sleep 3
curl -s "$KNXVAULT_ADDR/metrics" | grep knxvault_raft_commit_index

# 3. Search Raft data dirs on all pods — must NOT find canary plaintext
for i in 0 1 2; do
  echo "=== knxvault-$i ==="
  kubectl -n knxvault exec knxvault-$i -- sh -c \
    "grep -r '$CANARY' /var/lib/knxvault/raft 2>/dev/null && echo FAIL || echo OK: no plaintext in raft dir"
done

# 4. Confirm ciphertext is present (encrypted blob fields in snapshot JSON if inspecting Dragonboat snapshot files)
kubectl -n knxvault exec knxvault-0 -- find /var/lib/knxvault/raft -name '*.gob' -o -name 'snapshot*' 2>/dev/null | head -5

# 5. Read back via API — plaintext only at HTTP boundary
knxvault-cli kv get mt21/canary --show-secrets
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Canary string absent from `/var/lib/knxvault/raft` on all nodes |
| 2 | API read returns correct plaintext (decrypt at engine layer) |
| 3 | Backup export contains encrypted secret fields, not canary string |
| 4 | Document aligns with [ADR-0004](../adr/0004-encrypt-before-replication.md) |

---

## MT-22: Seal / unseal write gate

### Objective

Verify manual seal blocks mutating API paths while liveness probes keep serving.

### Procedure

```bash
# 1. Baseline write
knxvault-cli kv put mt22/seal value=open

# 2. Seal cluster (operator-initiated)
curl -s -X POST "$KNXVAULT_ADDR/sys/seal" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" -w "\n%{http_code}\n"

# 3. Mutating request rejected
curl -s -o /dev/null -w "%{http_code}" -X POST "$KNXVAULT_ADDR/secrets/kv/mt22/seal" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"value":"sealed"}}'
# Expect 503

# 4. Liveness still OK
curl -s "$KNXVAULT_ADDR/health" | jq .

# 5. Unseal (multi-share if configured; single-key dev)
curl -s -X POST "$KNXVAULT_ADDR/sys/unseal" \
  -H 'Content-Type: application/json' \
  -d '{"key":"'"$KNXVAULT_MASTER_KEY"'"}' | jq .

# 6. Writes resume
knxvault-cli kv put mt22/seal value=unsealed
knxvault-cli kv get mt22/seal --show-secrets
```

> Run on a maintenance window — seal blocks all secret engine writes cluster-wide.

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | `POST /sys/seal` succeeds |
| 2 | KV writes return 503 while sealed |
| 3 | `GET /health` returns 200 while sealed |
| 4 | Unseal restores write path; prior secrets intact |

---

## MT-23: Atomic backup with audit history

### Objective

Validate linearizable `snapshot.export`, optional audit inclusion, and cross-replica consistency.

### Procedure

```bash
# 1. Seed graph: KV + policy + PKI + audit events
knxvault-cli kv put mt23/atomic value=graph-test
curl -s -X POST "$KNXVAULT_ADDR/pki/root" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mt23-root","common_name":"MT23 Root","ttl":"720h"}' | jq -r .id

# 2. Backup without audit
curl -s -X POST "$KNXVAULT_ADDR/sys/backup" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"include_audit":false}' | jq -r '.data' | base64 -d > mt23-no-audit.json

# 3. Backup with audit
curl -s -X POST "$KNXVAULT_ADDR/sys/backup" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"include_audit":true}' | jq -r '.data' | base64 -d > mt23-with-audit.json

# 4. Compare sizes — audit variant larger
wc -c mt23-no-audit.json mt23-with-audit.json

# 5. Export twice in quick succession from different pods (port-forward) — CA + secret both present
for i in 0 1 2; do
  kubectl -n knxvault port-forward knxvault-$i 82$i:8200 &
done
sleep 2
# Inspect decrypted snapshot sections contain mt23/atomic AND mt23-root CA (via jq after dev decrypt or CLI inspect)
knxvault-cli backup create -o mt23-cli.json
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | `include_audit:true` backup contains audit entries |
| 2 | `include_audit:false` omits audit or ships empty audit section per format |
| 3 | Backup triggered Dragonboat on-disk snapshot (leader logs) |
| 4 | CA and KV secret appear together (no torn graph) |
| 5 | Archive uses `format: knxvault-backup` with encrypted payload |

---

## MT-24: Restore validation & negative cases

### Objective

Confirm `ValidateSnapshot` rejects corrupt archives before `snapshot.import` mutates state.

### Procedure

```bash
# 1. Valid restore (staging namespace or disposable cluster)
knxvault-cli backup create -o mt24-good.json
# On fresh cluster with same KNXVAULT_MASTER_KEY:
knxvault-cli backup restore -f mt24-good.json
knxvault-cli kv get mt23/atomic --show-secrets || knxvault-cli doctor

# 2. Wrong master key — must fail before import
WRONG_KEY=$(openssl rand -base64 32)
KNXVAULT_MASTER_KEY=$WRONG_KEY knxvault-cli backup restore -f mt24-good.json
# Expect decrypt/validation error

# 3. Tampered ciphertext — corrupt random byte in archive JSON
cp mt24-good.json mt24-bad.json
python3 -c "
import json
d=json.load(open('mt24-bad.json'))
d['ciphertext']=d['ciphertext'][:-4]+'XXXX'
json.dump(d,open('mt24-bad.json','w'))
"
knxvault-cli backup restore -f mt24-bad.json
# Expect failure

# 4. Broken audit chain in plaintext snapshot (lab only — craft invalid export)
# Expect ValidateSnapshot error referencing audit hash chain
```

See [`docs/deploy/backup-restore.md`](../deploy/backup-restore.md).

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Valid backup restores full KV + RBAC + PKI graph |
| 2 | Wrong master key rejected |
| 3 | Tampered archive rejected |
| 4 | Post-restore RBAC cache reloaded (policies effective without restart) |
| 5 | Raft `snapshot.import` replaces state atomically (no merge) |

---

## MT-25: Intermediate CA chain & leaf lifecycle

### Objective

Exercise multi-tier PKI: root → intermediate → leaf, renew, CRL, and optional OCSP.

### Procedure

```bash
# 1. Root CA
curl -s -X POST "$KNXVAULT_ADDR/pki/root" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mt25-root","common_name":"MT25 Root CA","ttl":"8760h"}' | jq .

# 2. Intermediate signed by root
curl -s -X POST "$KNXVAULT_ADDR/pki/intermediate" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"parent_name":"mt25-root","name":"mt25-int","common_name":"MT25 Intermediate CA","ttl":"4380h"}' | jq .

# 3. Issue leaf from intermediate (role = intermediate CA name)
curl -s -X POST "$KNXVAULT_ADDR/pki/issue" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role":"mt25-int","common_name":"app.mt25.example.com","dns_names":["app.mt25.example.com"],"ttl":"24h"}' \
  | jq '{serial, expires_at}' | tee mt25-leaf.json

SERIAL=$(jq -r .serial mt25-leaf.json)
INT_ID=$(curl -s "$KNXVAULT_ADDR/pki/ca/mt25-int" -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq -r .id)

# 4. Verify chain with openssl
jq -r .cert_pem mt25-leaf.json > leaf.pem
curl -s "$KNXVAULT_ADDR/pki/ca/$INT_ID/export" -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq -r .cert_pem > int.pem
openssl verify -CAfile int.pem -untrusted int.pem leaf.pem

# 5. Renew leaf
curl -s -X POST "$KNXVAULT_ADDR/pki/renew" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"ca_id\":\"$INT_ID\",\"serial\":\"$SERIAL\",\"ttl\":\"48h\"}" | jq .

# 6. Revoke + CRL + OCSP (if responder configured)
curl -s -X POST "$KNXVAULT_ADDR/pki/revoke" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"ca_id\":\"$INT_ID\",\"serial\":\"$SERIAL\",\"reason\":\"test\"}"
curl -s "$KNXVAULT_ADDR/pki/crl/$INT_ID" -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq -r .crl_pem | openssl crl -inform PEM -noout -text | grep -F "$SERIAL"
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Intermediate cert signed by root |
| 2 | Leaf chains to intermediate; `openssl verify` succeeds |
| 3 | Renew returns new serial, preserves CA binding |
| 4 | Revoked serial appears in CRL |
| 5 | `issued` metadata tracked (`GET /pki/ca/:id` lists expiring certs when exposed) |

---

## MT-26: CA import, rotate, export

### Objective

Validate external CA material import, in-place CA key rotation, and PEM export for trust distribution.

### Procedure

```bash
# 1. Generate external CA (openssl)
openssl req -x509 -newkey rsa:2048 -keyout mt26-ca.key -out mt26-ca.pem -days 365 -nodes \
  -subj "/CN=MT26 External CA"

# 2. Import into KNXVault
curl -s -X POST "$KNXVAULT_ADDR/pki/ca/import" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"mt26-imported\",\"common_name\":\"MT26 External CA\",\"cert_pem\":\"$(awk '{printf "%s\\n",$0}' mt26-ca.pem)\",\"key_pem\":\"$(awk '{printf "%s\\n",$0}' mt26-ca.key)\"}" | jq .

CA_ID=$(curl -s "$KNXVAULT_ADDR/pki/ca/mt26-imported" -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq -r .id)

# 3. Issue leaf from imported CA
curl -s -X POST "$KNXVAULT_ADDR/pki/issue" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"role\":\"mt26-imported\",\"common_name\":\"imported.mt26.example.com\",\"ttl\":\"12h\"}" | jq .

# 4. Rotate CA key (generates new key material; document client trust update)
curl -s -X POST "$KNXVAULT_ADDR/pki/ca/$CA_ID/rotate" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .

# 5. Export rotated CA for trust store
curl -s "$KNXVAULT_ADDR/pki/ca/$CA_ID/export" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq -r .cert_pem > mt26-exported.pem
openssl x509 -in mt26-exported.pem -noout -subject -dates
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Import succeeds; CA readable via `GET /pki/ca/:id` |
| 2 | Leaf issued from imported CA validates against exported PEM |
| 3 | Rotate returns new cert serial/dates |
| 4 | Export PEM suitable for workload trust bundles |
| 5 | Private key never appears in audit export or Raft plaintext (MT-21 cross-check) |

---

## MT-27: Database dynamic credentials & leases

### Objective

Validate the database secrets engine: role CRUD, credential generation, lease renew/revoke, and optional live PostgreSQL execution.

### Procedure

```bash
# Prerequisite: PostgreSQL reachable from cluster (CNPG, RDS, or test pod).
# Store admin creds in KV for managed mode:
knxvault-cli kv put mt27/db/admin username=postgres password='<admin-pass>'

# 1. Define role
curl -s -X PUT "$KNXVAULT_ADDR/secrets/database/roles/mt27-app" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "ttl_seconds": 300,
    "username_prefix": "v_",
    "creation_statements": ["CREATE USER \"{{username}}\" WITH PASSWORD '\''{{password}}'\'' LOGIN;"],
    "revocation_statements": ["DROP USER IF EXISTS \"{{username}}\";"],
    "execution_mode": "managed",
    "admin_credentials_path": "mt27/db/admin",
    "config": {"plugin": "postgres", "connection_url": "postgres://{{username}}:{{password}}@postgres.default.svc:5432/appdb"}
  }'

# 2. Generate creds
curl -s -X POST "$KNXVAULT_ADDR/secrets/database/creds/mt27-app" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ttl_seconds":300}' | jq . > mt27-creds.json

LEASE=$(jq -r .lease_id mt27-creds.json)

# 3. Connect with generated creds (psql or pg_isready)
PGUSER=$(jq -r .username mt27-creds.json) PGPASSWORD=$(jq -r .password mt27-creds.json) \
  psql -h postgres.default.svc -d appdb -c 'SELECT 1'

# 4. Renew lease
curl -s -X POST "$KNXVAULT_ADDR/secrets/database/renew/$LEASE" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ttl_seconds":600}' | jq .

# 5. Revoke / wait for TTL — user dropped
# knxvault-cli lease revoke $LEASE  (when CLI wired)
curl -s "$KNXVAULT_ADDR/metrics" | grep knxvault_active_leases
```

CLI: `knxvault-cli database roles put`, `knxvault-cli database creds mt27-app`.

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Role persisted and returned by `GET /secrets/database/roles/mt27-app` |
| 2 | `creds` returns unique username/password + `lease_id` |
| 3 | DB login succeeds with generated creds (managed mode) |
| 4 | Renew extends `expires_at` |
| 5 | Revocation/TTL expiry removes DB user; audit records issue/renew |

---

## MT-28: SSH signed user certificates

### Objective

Validate OpenSSH engine: CA key in KV, role binding, signed cert output, lease tracking.

### Procedure

```bash
# 1. Generate SSH CA keypair and store private key in KV (encrypted)
ssh-keygen -t ed25519 -f mt28-ca -N "" -C "mt28-ssh-ca"
knxvault-cli kv put mt28/ssh/ca/private-key value="$(cat mt28-ca)"

# 2. Define SSH role
curl -s -X PUT "$KNXVAULT_ADDR/secrets/ssh/roles/mt28-ops" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "ttl_seconds": 600,
    "ca_key_path": "mt28/ssh/ca/private-key",
    "allowed_users": ["deploy"],
    "default_user": "deploy"
  }'

# 3. Issue credentials
curl -s -X POST "$KNXVAULT_ADDR/secrets/ssh/creds/mt28-ops" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"deploy","ttl_seconds":600}' | jq . > mt28-ssh.json

# 4. Validate signed cert against CA public key
jq -r .signed_key mt28-ssh.json > mt28-cert.pub
ssh-keygen -L -f mt28-cert.pub
ssh-keygen -Y check -n user -I "$(ssh-keygen -L -f mt28-cert.pub | awk '/Signing CA/ {print $3}')" -s mt28-ca.pub < mt28-cert.pub

# 5. Optional: ssh -i user_key -o CertificateFile=mt28-cert.pub deploy@target
```

CLI: `knxvault-cli ssh roles put`, `knxvault-cli ssh creds mt28-ops --username deploy`.

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Role requires valid `ca_key_path` in KV |
| 2 | Response includes `signed_key`, `private_key`, `lease_id` |
| 3 | `ssh-keygen -L` shows principals and validity window |
| 4 | Cert verifies against CA with `ssh-keygen -Y check` |
| 5 | Wrong `allowed_users` rejected |

---

## MT-29: Orchestrated rotation job

### Objective

Trigger `POST /sys/rotation/run` and confirm leader-coordinated rotation across KV, database, and PKI schedules.

### Procedure

```bash
# 1. Configure rotatable KV secret with metadata (per rotation docs)
knxvault-cli kv put mt29/rotatable value=version-1

# 2. Record pre-rotation metrics / audit
curl -s "$KNXVAULT_ADDR/metrics" | grep -E 'rotation|lease' || true

# 3. Trigger orchestrated rotation (leader only)
curl -s -X POST "$KNXVAULT_ADDR/sys/rotation/run" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{}' | jq .

# 4. Inspect leader logs for rotation job
LEADER_POD=$(kubectl -n knxvault get pods -l app.kubernetes.io/name=knxvault -o json \
  | jq -r '.items[] | select(.status.phase=="Running") | .metadata.name' | head -1)
kubectl -n knxvault logs "$LEADER_POD" --tail=100 | grep -i rotation

# 5. Verify side effects (new KV version, renewed lease, or PKI re-issue per config)
knxvault-cli kv get mt29/rotatable --show-secrets
curl -s "$KNXVAULT_ADDR/audit/export?limit=20" -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  | jq '.entries | map(select(.action|test("rotation")))'
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | `rotation/run` returns success when invoked via leader/service |
| 2 | Rotation work logged on leader pod |
| 3 | At least one configured rotatable target updates |
| 4 | Audit captures rotation events |
| 5 | Idempotent re-run does not corrupt state |

---

## MT-30: Mutating admission webhook injection

### Objective

Deploy `knxvault-webhook` and verify annotation-driven CSI volume injection at pod admission.

### Procedure

```bash
# 1. Label namespace for webhook
kubectl label namespace default knxvault.io/webhook=enabled --overwrite

# 2. Deploy webhook
kubectl apply -f deployments/k8s/webhook/deployment.yaml
kubectl apply -f deployments/k8s/webhook/mutating-webhook.yaml
kubectl -n knxvault wait --for=condition=available deployment/knxvault-webhook --timeout=120s

# 3. Ensure SecretProviderClass exists (from MT-12)
kubectl apply -f deployments/csi/secretproviderclass-example.yaml

# 4. Create pod with inject annotations (no manual CSI volume)
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: mt30-webhook-inject
  namespace: default
  annotations:
    knxvault.io/inject: "true"
    knxvault.io/secret-provider-class: knxvault-app-db
    knxvault.io/inject-mount-path: /mnt/secrets
spec:
  serviceAccountName: demo-app
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
EOF

# 5. Verify mutated spec
kubectl get pod mt30-webhook-inject -o json | jq '.spec.volumes[] | select(.csi.driver=="secrets-store.csi.k8s.io")'
kubectl get pod mt30-webhook-inject -o json | jq '.spec.containers[0].volumeMounts'

# 6. Negative — missing SPC annotation should fail admission
kubectl apply -f - <<'EOF' || true
apiVersion: v1
kind: Pod
metadata:
  name: mt30-webhook-bad
  namespace: default
  annotations:
    knxvault.io/inject: "true"
spec:
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "60"]
EOF
```

See [`docs/integration/kubernetes-native.md`](../integration/kubernetes-native.md).

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | Webhook injects CSI volume + mount when annotations valid |
| 2 | Pod reaches Ready and secret file readable at mount path |
| 3 | Namespace without `knxvault.io/webhook=enabled` is not mutated |
| 4 | Missing `secret-provider-class` annotation fails admission (`failurePolicy: Fail`) |
| 5 | Idempotent — re-apply does not duplicate volumes |

---

## MT-31: External Secrets Operator webhook sync

### Objective

Validate `knxvault-eso` webhook provider syncs KV paths into native Kubernetes `Secret` objects.

### Procedure

```bash
# 1. Seed KV secret
knxvault-cli kv put app/db password='eso-sync-pass' username='appuser'

# 2. Deploy ESO adapter + ClusterSecretStore
make build-eso
kubectl apply -f deployments/external-secrets/knxvault-eso-deployment.yaml
kubectl apply -f deployments/external-secrets/clustersecretstore-webhook.yaml

# 3. Install ESO controller (if not present)
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace

# 4. Apply ExternalSecret
kubectl apply -f deployments/external-secrets/externalsecret-example.yaml
kubectl wait --for=condition=ready externalsecret/app-db -n default --timeout=180s

# 5. Verify native Secret
kubectl get secret app-db-credentials -o jsonpath='{.data.password}' | base64 -d; echo
kubectl get secret app-db-credentials -o jsonpath='{.data.username}' | base64 -d; echo

# 6. Rotate KV; wait refreshInterval; confirm Secret updates
knxvault-cli kv put app/db password='eso-rotated' username='appuser'
sleep 65  # or lower refreshInterval for test
kubectl get secret app-db-credentials -o jsonpath='{.data.password}' | base64 -d; echo
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | ExternalSecret reaches `Ready=True` |
| 2 | Target `Secret` created with keys from `remoteRef` |
| 3 | Values match KV path `app/db` |
| 4 | KV update propagates after refresh interval |
| 5 | ESO adapter logs show TokenReview auth (no static root token in adapter) |

---

## MT-32: cert-manager Vault issuer sign flow

### Objective

Demonstrate cert-manager obtaining certificates via KNXVault Vault API shim (`/v1/auth/kubernetes/login`, `/v1/pki/sign/:role`).

### Procedure

```bash
# 1. PKI role for web servers (see deployments/cert-manager/)
curl -s -X POST "$KNXVAULT_ADDR/pki/root" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"cm-root","common_name":"CM Root","ttl":"8760h"}'

# 2. Bind cert-manager SA role
curl -s -X PUT "$KNXVAULT_ADDR/sys/roles/cert-manager" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"policies":["pki-issuer"],"bound_service_account_names":["cert-manager"],"bound_service_account_namespaces":["cert-manager"]}'

# 3. Install cert-manager + ClusterIssuer
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.4/cert-manager.yaml
kubectl apply -f deployments/cert-manager/clusterissuer-knxvault.yaml

# 4. Request Certificate
kubectl apply -f - <<'EOF'
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: mt32-demo
  namespace: default
spec:
  secretName: mt32-demo-tls
  issuerRef:
    name: knxvault-pki
    kind: ClusterIssuer
  dnsNames:
    - mt32.example.com
EOF

kubectl wait --for=condition=ready certificate/mt32-demo --timeout=300s
kubectl get secret mt32-demo-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -subject -dates
```

### Pass criteria

| # | Criterion |
|---|-----------|
| 1 | cert-manager authenticates via `POST /v1/auth/kubernetes/login` |
| 2 | CSR signed via `POST /v1/pki/sign/:role` |
| 3 | `Certificate` reaches `Ready=True` |
| 4 | TLS secret contains valid cert chaining to KNXVault CA |
| 5 | Renewal occurs before expiry (cert-manager auto-renew) |

---

## 5. Recommended execution order

```mermaid
flowchart TD
  mt00[MT-00 Deploy 3-node]
  mt14[MT-14 Metrics/health]
  mt03[MT-03 KV lifecycle]
  mt08[MT-08 K8s auth]
  mt09[MT-09 OIDC auth]
  mt10[MT-10 RBAC]
  mt13[MT-13 PKI]
  mt12[MT-12 CSI]
  mt02[MT-02 Rotation latency]
  mt11[MT-11 Audit SIEM]
  mt04[MT-04 Master key rotate]
  mt05[MT-05 Leader failover]
  mt06[MT-06 Remove/re-add node]
  mt01[MT-01 Network partition]
  mt07[MT-07 Backup restore]
  mt15[MT-15 Rolling upgrade]
  report[POC evidence report]

  mt00 --> mt14 --> mt03
  mt03 --> mt08 --> mt09 --> mt10
  mt10 --> mt13 --> mt12 --> mt02 --> mt11
  mt11 --> mt04 --> mt05 --> mt06 --> mt01 --> mt07 --> mt15 --> report
```

Run disruptive tests (**MT-01**, **MT-05**, **MT-06**, **MT-15**) after functional baselines. Take backup before **MT-04**, **MT-07**, **MT-15**.

Subsystem deep-dives (Section 4) run after **MT-03** / **MT-07** baselines. Suggested order:

```mermaid
flowchart LR
  raft[MT-16–18 Raft]
  audit[MT-19–20 Audit]
  store[MT-21–22 Storage]
  backup[MT-23–24 Backup]
  pki[MT-25–26 PKI]
  engines[MT-27–29 Engines]
  k8s[MT-30–32 K8s]

  raft --> audit --> store --> backup --> pki --> engines --> k8s
```

---

## 6. POC demonstration checklist

Use this single-page checklist for prospect demos:

| # | Demonstration | Test ID | Pass |
|---|---------------|---------|------|
| 1 | Deploy 3-node cluster | MT-00 | ☐ |
| 2 | Store, update, version, retrieve secrets | MT-03 | ☐ |
| 3 | Rotate master key without data loss | MT-04 | ☐ |
| 4 | Kill leader → automatic failover | MT-05 | ☐ |
| 5 | Remove and re-add node | MT-06 | ☐ |
| 6 | Backup and restore | MT-07 | ☐ |
| 7 | Kubernetes SA authentication | MT-08 | ☐ |
| 8 | OIDC authentication | MT-09 | ☐ |
| 9 | Enforce RBAC policies | MT-10 | ☐ |
| 10 | Export audit / SIEM forwarding | MT-11 | ☐ |
| 11 | Secrets Store CSI Driver | MT-12 | ☐ |
| 12 | Certificate issue & revoke | MT-13 | ☐ |
| 13 | Prometheus metrics & health | MT-14 | ☐ |
| 14 | Rolling upgrade without downtime | MT-15 | ☐ |
| 15 | Network disruption recovery | MT-01 | ☐ |
| 16 | Secret rotation latency (no restart) | MT-02 | ☐ |

### Subsystem deep-dive checklist (engineering)

| Area | Test IDs | Pass |
|------|----------|------|
| Dragonboat / Raft | MT-16, MT-17, MT-18 | ☐ |
| Audit subsystem | MT-19, MT-20 | ☐ |
| Storage / repository | MT-21, MT-22 | ☐ |
| Backup and restore (advanced) | MT-23, MT-24 | ☐ |
| PKI internals | MT-25, MT-26 | ☐ |
| Secret engines | MT-27, MT-28, MT-29 | ☐ |
| K8s controllers / webhooks | MT-30, MT-31, MT-32 | ☐ |

---

## 7. Reporting for BFSI / prospect evaluation

Include in the test report:

1. Completed checklist (Section 5) with pass/fail and timestamps
2. Environment diagram — nodes, CNI, CSI, IdP, SIEM
3. Failover and upgrade error windows (seconds of write unavailability)
4. Rotation latency table (MT-02)
5. Known limitations — path-level RBAC (W41-01), OIDC role API (W43-06)
6. Link to [`../audit/formal-code-audit-2026.md`](../audit/formal-code-audit-2026.md)
7. Subsystem deep-dive checklist (Section 6) for engineering sign-off

---

## 8. Related documents

- [Automated testing guide](testing.md)
- [Kubernetes deployment](../deploy/kubernetes.md)
- [Raft failover runbook](../operations/runbooks/raft-failover.md)
- [Scaling runbook](../operations/runbooks/scaling.md)
- [Backup & restore](../deploy/backup-restore.md)
- [CSI install](../deploy/csi-install.md)
- [Audit forwarding](../observability/audit-forwarding.md)
- [Day-2 operations](../operations/day2.md)
- [BFSI POC traceability](../product/bfsi-poc-traceability.md)
- [Dragonboat storage](../storage/dragonboat.md)
- [Raft HA & recovery](../storage/raft-ha-and-recovery.md)
- [Kubernetes-native integrations](../integration/kubernetes-native.md)

---

**Document control**

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-07-01 | Initial: MT-01 network disruption, MT-02 rotation latency |
| 1.1 | 2026-07-01 | Full POC pack MT-00–MT-15; demonstration checklist |
| 1.2 | 2026-07-01 | Subsystem deep-dives MT-16–MT-32 (Raft, audit, storage, backup, PKI, engines, K8s) |