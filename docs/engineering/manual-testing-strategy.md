# Manual Testing Strategy

Structured manual test procedures for validating KNXVault behavior beyond automated unit and integration tests. Use these exercises before BFSI POC sign-off, after infrastructure changes, or when validating HA and secret-delivery assumptions in a target cluster.

| Field | Value |
|-------|-------|
| **Version** | 1.0 |
| **Last updated** | 2026-07-01 |
| **Audience** | QA, SRE, security engineers, prospect evaluators |
| **Complements** | [`testing.md`](testing.md) (automated), [`../operations/runbooks/raft-failover.md`](../operations/runbooks/raft-failover.md) |

---

## 1. Purpose and scope

Automated tests (`make test`, `make test-integration`, `test/chaos/raft-pod-kill.sh`) prove correctness on a developer machine. **Manual tests** validate:

- Real network partitions between Raft peers (not just process kill)
- End-to-end secret **propagation latency** into running workloads without restart
- Operator-visible symptoms (metrics, `/ready`, audit, CLI)
- Environment-specific wiring (CNI, NetworkPolicy, CSI rotation, ingress TLS)

This document defines **repeatable procedures**, **pass/fail criteria**, and **evidence to capture**. It does not replace penetration testing or load benchmarks (see backlog **LT-12**).

---

## 2. Test environment matrix

| Profile | When to use | Minimum topology |
|---------|-------------|------------------|
| **A — Local multi-process** | Fast iteration; no Kubernetes | 3× `knxvault serve` on `127.0.0.1:63001–63003` with distinct `KNXVAULT_RAFT_NODE_ID` |
| **B — Kubernetes StatefulSet** | Production-like; **recommended for MT-01/MT-02** | 3-node Raft per [`deploy/kubernetes.md`](../deploy/kubernetes.md) |
| **C — kind + CSI** | Rotation latency with volume mounts | Profile B + [CSI install](../deploy/csi-install.md) (`enableSecretRotation=true`) |

### Prerequisites (all profiles)

- [ ] `KNXVAULT_MASTER_KEY` and `KNXVAULT_ROOT_TOKEN` configured; root token rotated or disabled after bootstrap policies exist
- [ ] `KNXVAULT_RAFT_ENABLED=true` with 3 voting members and persistent Raft data dirs / PVCs
- [ ] `knxvault-cli` and `curl` available; Prometheus scraping `/metrics` (optional but recommended)
- [ ] Baseline backup taken: `knxvault-cli backup create -o pre-test-backup.json`

### Evidence template (per test run)

Record in your test report or ticket:

| Field | Example |
|-------|---------|
| Test ID | MT-01 |
| Date / operator | 2026-07-01 / alice |
| Profile | B (K8s 1.30, 3-node StatefulSet) |
| KNXVault version | `knxvault-cli version` output |
| Pass / Fail | Pass |
| Notes | Minority partition recovered in 42s; no auto-seal observed |
| Attachments | `metrics.txt`, `audit-export.json`, screenshots |

---

## 3. Test catalog

| ID | Name | Priority | Profile |
|----|------|----------|---------|
| **MT-01** | [Network disruption & Raft recovery](#mt-01-network-disruption--raft-recovery) | P0 | A or B |
| **MT-02** | [Secret rotation latency (no pod restart)](#mt-02-secret-rotation-latency-without-workload-restart) | P0 | B + C |
| MT-03 | Seal / unseal operator workflow | P1 | B |
| MT-04 | Backup → restore round-trip | P1 | B |
| MT-05 | Leader failover under write load | P1 | B |

MT-03–MT-05 are summarized in [Section 6](#6-additional-recommended-manual-tests); MT-01 and MT-02 are fully specified below per evaluation requirements.

---

## MT-01: Network disruption & Raft recovery

### Objective

Spin up a 3-node vault cluster, store secrets, **intentionally disrupt network connectivity between Raft peers**, and observe:

1. Whether the vault **auto-seals** (it should **not** in current product behavior)
2. Whether the **majority partition** continues to serve reads/writes
3. Whether the **minority partition** recovers and **re-synchronizes** when connectivity is restored

### Expected product behavior (baseline)

| Behavior | Current KNXVault |
|----------|------------------|
| Auto-seal on network loss | **No** — seal is **operator-initiated** only (`POST /sys/seal` / `knxvault-cli sys seal`). Network partition does not trigger seal. |
| Minority partition writes | **Rejected** — Raft requires quorum (2/3). |
| Majority partition writes | **Continue** — new leader elected if leader was isolated. |
| Recovery after heal | **Automatic** — Dragonboat replicates committed log; lagging node catches up. |
| Data loss (quorum intact) | **None** for committed writes. |

Document any deviation from this table as a **defect**.

### Setup

**Profile B (recommended):**

```bash
kubectl apply -f deployments/k8s/namespace.yaml
kubectl apply -f deployments/k8s/secret.yaml
kubectl apply -f deployments/k8s/configmap.yaml
kubectl apply -f deployments/k8s/statefulset.yaml
# ... remaining manifests per deploy/kubernetes.md
kubectl -n knxvault wait --for=condition=ready pod -l app.kubernetes.io/name=knxvault --timeout=300s
```

**Profile A (local):** start three processes with shared `KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001,2=127.0.0.1:63002,3=127.0.0.1:63003` and distinct data dirs (see [`testing.md`](testing.md#single-node-raft-manual-test) — repeat for nodes 2 and 3).

### Phase 1 — Baseline (healthy cluster)

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<root-or-admin-token>

# Health
knxvault-cli doctor
curl -s "$KNXVAULT_ADDR/ready" | jq .

# Store test secrets (record paths and versions)
knxvault-cli kv put mt01/secret-a value=baseline-a
knxvault-cli kv put mt01/secret-b value=baseline-b
knxvault-cli kv get mt01/secret-a

# Capture Raft baseline from each pod (or local ports)
for i in 0 1 2; do
  kubectl -n knxvault exec knxvault-$i -- wget -qO- http://localhost:8200/metrics \
    | grep -E 'knxvault_raft_(leader|term|commit_index)' || true
done

# Confirm NOT sealed
curl -s -o /dev/null -w "%{http_code}" -X POST "$KNXVAULT_ADDR/secrets/kv/mt01/probe" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" -H 'Content-Type: application/json' \
  -d '{"data":{"x":"1"}}'
# Expect 200 or 204 on success path (not 503 sealed)
```

Record: leader pod name, `knxvault_raft_commit_index` on all nodes, secret values.

### Phase 2 — Induce network disruption

Choose **one** isolation method (document which you used):

#### Option A — Kubernetes NetworkPolicy (one-way isolate minority)

Create a deny-all policy targeting **one** replica (e.g. `knxvault-2`) while leaving peers reachable to each other. Example pattern:

```yaml
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
  # No ingress/egress rules => default deny
```

```bash
kubectl apply -f mt01-isolate-knxvault-2.yaml
```

#### Option B — CNI / node firewall (Raft port 63001)

On the node hosting `knxvault-2`, block TCP **63001** to/from other vault pod IPs (Cilium `NetworkPolicy`, `iptables`, or `tc netem` loss/delay). Preserve port **8200** if testing HTTP-only isolation separately.

#### Option C — Local profile A — `iptables` on loopback

```bash
# Block node 2 ↔ nodes 1,3 on Raft ports (adjust interfaces/ports)
sudo iptables -A INPUT -s 127.0.0.1 -p tcp --dport 63002 -j DROP
sudo iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 63002 -j DROP
```

### Phase 3 — Observe during partition (15–30 minutes)

Run on a schedule (every 60s); capture timestamps.

| Check | Command / signal | Majority (2 nodes) | Minority (1 node) |
|-------|------------------|--------------------|-------------------|
| HTTP ready | `GET /ready` per pod | `ready: true`, `raft_ready: true` | Often `raft_ready: false` or stale `leader` |
| Sealed? | Mutating KV `PUT` | **Must succeed** (not 503) unless manually sealed | May fail (no quorum) — **not** proof of auto-seal |
| Explicit seal state | `GET /health` + try `sys seal` status via write | Unsealed | Unsealed unless operator sealed |
| Leader metric | `knxvault_raft_leader` | Exactly one `1` on majority side | Leader gauge may be 0 or inconsistent |
| Read secret | `knxvault-cli kv get mt01/secret-a` via Service | Returns `baseline-a` | May fail or lag |
| Write new secret | `kv put mt01/secret-c` | Should succeed on majority | Should **fail** with clear error |
| Audit | `GET /audit/export` (subset) | New entries for successful writes | Failed writes logged |

**Auto-seal check:** If mutating API returns **503** with a sealed message, verify whether an operator ran `sys seal` or config triggered seal. **Network loss alone must not seal the vault.**

### Phase 4 — Restore connectivity

```bash
kubectl delete networkpolicy mt01-isolate-knxvault-2 -n knxvault
# or remove iptables / tc rules
```

### Phase 5 — Recovery verification

Within **5 minutes** of heal (adjust for your RTT):

```bash
# All pods ready
kubectl -n knxvault wait --for=condition=ready pod -l app.kubernetes.io/name=knxvault --timeout=180s

# Single leader
curl -s localhost:8200/metrics | grep knxvault_raft_leader  # after port-forward

# Data intact + new write
knxvault-cli kv get mt01/secret-a
knxvault-cli kv get mt01/secret-c   # written during majority partition
knxvault-cli kv put mt01/secret-d value=after-heal

# Commit index monotonic (compare to Phase 1 notes)
```

### Pass criteria — MT-01

| # | Criterion |
|---|-----------|
| 1 | Majority partition accepted writes during partition (quorum intact) |
| 2 | Minority partition did **not** accept quorum writes |
| 3 | Vault did **not** auto-seal solely due to network disruption |
| 4 | After heal, all 3 nodes report `ready`; exactly one Raft leader |
| 5 | Secrets written before and during partition readable after heal |
| 6 | `knxvault_raft_commit_index` on isolated node catches up to majority |

### Fail / investigate

- Unexpected **503 sealed** without operator action → bug or runbook gap
- Split-brain **dual writers** accepting conflicting writes → critical; stop test and review `KNXVAULT_RAFT_INITIAL_MEMBERS`
- Permanent commit index stall after heal → storage or Raft defect; collect logs from all pods

### References

- [Raft failover runbook](../operations/runbooks/raft-failover.md) — Scenario 5 (network partition)
- [Raft HA & recovery](../storage/raft-ha-and-recovery.md)
- Chaos script (pod kill, not partition): `test/chaos/raft-pod-kill.sh`

---

## MT-02: Secret rotation latency (without workload restart)

### Objective

Measure **how quickly** a credential rotated inside KNXVault appears in a **running** application **without** restarting the pod, container, or VM.

This test is **consumption-path dependent**. KNXVault rotates secrets in storage immediately; **propagation** depends on CSI rotation polling, ESO refresh, or application behavior.

### Consumption paths

| Path | Hot reload without restart? | Primary control |
|------|----------------------------|-----------------|
| **CSI volume mount** (recommended) | **Yes** — driver re-mounts / refreshes files | `enableSecretRotation=true` (Helm) + `rotationPollInterval` on `SecretProviderClass` |
| **CSI + `secretObjects` sync** | **Partial** — synced K8s `Secret` updates; pods using `envFrom` may need rollout unless app reloads env | Driver sync + app design |
| **External Secrets Operator** | **Yes** — refreshes target `Secret` on interval | `ExternalSecret.spec.refreshInterval` |
| **Sidecar / `inject/render`** | **No** (default) — one-shot at startup | Requires custom reload sidecar (out of scope) |
| **Dynamic DB/SSH leases** | **N/A** — apps must **reconnect** with new creds; not file-based hot swap | `POST /secrets/database/creds`, lease renewal |

MT-02 focuses on **KV via CSI** (Profile C). Document other paths as supplementary if your POC uses them.

### Setup — Profile C

1. Deploy KNXVault (Profile B).
2. Install CSI driver with rotation:

```bash
helm install csi secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system \
  --set syncSecret.enabled=true \
  --set enableSecretRotation=true
kubectl apply -f deployments/csi/rbac.yaml
kubectl apply -f deployments/csi/k8s-provider.yaml
```

3. Create a dedicated test `SecretProviderClass` with a **short** poll interval for measurement:

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: mt02-rotation-test
  namespace: default
spec:
  provider: knxvault
  rotationPollInterval: 30s   # use 30s for test; production often 2m+
  parameters:
    vaultAddr: "https://knxvault.knxvault.svc.cluster.local:8200"
    role: <workload-role>
    objects: |
      - path: mt02/app-cred
        fileName: cred.txt
        objectType: secret
```

4. Deploy a long-running pod that **reads the file in a loop** (no restart):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mt02-reader
  namespace: default
spec:
  serviceAccountName: <bound-sa>
  containers:
    - name: reader
      image: busybox:1.36
      command: ["/bin/sh", "-c"]
      args:
        - |
          while true; do
            date -Iseconds
            cat /mnt/secrets/cred.txt 2>/dev/null || echo MISSING
            sleep 5
          done
      volumeMounts:
        - name: secrets
          mountPath: /mnt/secrets
          readOnly: true
  volumes:
    - name: secrets
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: mt02-rotation-test
```

5. Seed the secret and confirm the pod sees version 1:

```bash
knxvault-cli kv put mt02/app-cred value=version-1
kubectl logs mt02-reader -f   # observe version-1 in file
```

6. Configure KV rotation (optional — for automated rotation) or rotate manually:

```bash
# Manual rotation (immediate new version)
knxvault-cli kv put mt02/app-cred value=version-2

# Or scheduled rotation policy + orchestration:
# PUT /sys/kv-rotation + POST /sys/rotation/run
```

Record **T_rotate** = UTC timestamp when rotation API returns success (or orchestration webhook fires).

### Measurement procedure

1. **Do not restart** `mt02-reader` (no `kubectl delete pod`, no rollout).
2. Tail pod logs and watch for file content change to `version-2`.
3. Record **T_visible** = first log line showing new value.
4. **Latency** = `T_visible - T_rotate`.

Repeat **3 times**; report min / median / max.

Optional precision: exec into pod and `stat /mnt/secrets/cred.txt` when mtime or inode changes.

```bash
kubectl exec mt02-reader -- sh -c 'while true; do stat /mnt/secrets/cred.txt; sleep 2; done'
```

### Expected bounds

| Configuration | Expected latency (indicative) |
|---------------|-------------------------------|
| `rotationPollInterval: 30s` | **0–30s** after rotation (typically next poll cycle) |
| `rotationPollInterval: 2m` | **0–120s** |
| No `enableSecretRotation` | **No update** without pod restart — **fail** for hot-reload requirement |

CSI driver behavior follows [Secrets Store CSI rotation](https://secrets-store-csi-driver.sigs.k8s.io/topics/secret-auto-rotation.html); KNXVault exposes new KV versions via the provider mount path (**W39-05**).

### Pass criteria — MT-02

| # | Criterion |
|---|-----------|
| 1 | New secret version visible in mounted file **without** pod restart |
| 2 | Median latency ≤ `rotationPollInterval` + 15s buffer (account for poll jitter) |
| 3 | `knxvault_csi_mount_rotations_total` (if scraped) increments after rotation |
| 4 | Audit shows `secret.rotate` or KV write; CSI mount audit if enabled |
| 5 | Application log shows **no** crash loop during rotation |

### Supplement — ESO path

If the POC uses External Secrets Operator instead of direct CSI file mount:

1. Create `ExternalSecret` with `refreshInterval: 30s` pointing at KNXVault KV.
2. Rotate KV secret; measure time until `kubectl get secret <target> -o jsonpath='{.data}'` changes.
3. Note: pods mounting that Secret via `envFrom` still require app reload unless using reloader — document separately.

### Supplement — Dynamic database credentials

Rotating a **lease** (`POST /sys/rotation/run` renewing DB creds) does **not** update files in place. Pass criteria for DB-backed apps:

- Measure time to **new lease issuance** (API) separately from app **reconnect** time.
- Do not conflate with MT-02 KV file latency unless the app reads creds from a CSI-mounted KV path.

### Fail / investigate

- No file update after 2× `rotationPollInterval` → check Helm `enableSecretRotation`, SPC annotation, provider logs (`kubectl logs -l app.kubernetes.io/name=knxvault-csi-provider`)
- Pod restart required to see new value → rotation pipeline not wired; fail hot-reload requirement
- Stale value with increasing rotation metric → provider/cache bug

### References

- [CSI install](../deploy/csi-install.md)
- [Secrets injection](../deploy/secrets-injection.md) — Rotation section
- Example SPC: `deployments/csi/secretproviderclass-example.yaml`
- Integration script: `scripts/test-csi-kind.sh`

---

## 4. Execution order (recommended POC pack)

```mermaid
flowchart LR
  baseline[Baseline deploy + doctor]
  mt01[MT-01 Network disruption]
  heal[Recovery verify + backup]
  mt02[MT-02 Rotation latency]
  report[Evidence report]

  baseline --> mt01 --> heal --> mt02 --> report
```

Run **MT-01** before **MT-02** so the cluster is known-good after partition testing.

---

## 5. Reporting for BFSI / prospect evaluation

Include in the test report:

1. **Environment diagram** — 3 nodes, CNI, CSI, ingress
2. **MT-01** — auto-seal observation (yes/no), recovery time, data integrity
3. **MT-02** — rotation latency table (min/median/max), `rotationPollInterval` used
4. **Waivers** — e.g. sidecar-only consumers (no hot reload), manual seal procedure
5. Link to [`../audit/formal-code-audit-2026.md`](../audit/formal-code-audit-2026.md) for known production gaps

---

## 6. Additional recommended manual tests

| ID | Summary | Procedure pointer |
|----|---------|-------------------|
| MT-03 | Seal / unseal | `knxvault-cli sys seal`; verify 503 on writes; `sys unseal`; [`cli/reference.md`](../cli/reference.md) |
| MT-04 | Backup / restore | `backup create` → destroy test path → `backup restore`; [`backup-restore.md`](../deploy/backup-restore.md) |
| MT-05 | Leader failover under load | `test/chaos/raft-pod-kill.sh` while running `kv put` loop in background |

---

## 7. Related documents

- [Automated testing guide](testing.md)
- [Development guide](development.md)
- [Raft failover runbook](../operations/runbooks/raft-failover.md)
- [Backup & restore](../deploy/backup-restore.md)
- [BFSI POC traceability](../product/bfsi-poc-traceability.md)
- [Formal code audit](../audit/formal-code-audit-2026.md)

---

**Document control**

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-07-01 | Initial strategy; MT-01 network disruption, MT-02 rotation latency |