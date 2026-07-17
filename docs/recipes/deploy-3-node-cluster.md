# Recipe: Deploy a 3-node cluster

Deploy a production-like highly available KNXVault cluster on Kubernetes using Dragonboat Raft.

## What you will learn

- How KNXVault maps StatefulSet pods to Raft node IDs
- Which manifests to apply and in what order
- How to verify quorum, leader election, and API health

## Prerequisites

- Kubernetes 1.28+ with default StorageClass for PVCs
- `kubectl`, `curl`, `jq`
- Container image built and tagged (or use a published image)

## Concepts

| Concept | Detail |
|---------|--------|
| **Raft cluster** | 3 voting members; writes need majority (2/3) |
| **Node IDs** | `knxvault-0` → `1`, `knxvault-1` → `2`, `knxvault-2` → `3` (auto-derived from pod name) |
| **Raft port** | `63001` (headless Service DNS) |
| **HTTP API** | `8200` (ClusterIP Service) |
| **Leader jobs** | Background rotation and re-encrypt run only on the elected leader |

```
  knxvault-0 (id=1) ──┐
  knxvault-1 (id=2) ──┼── Raft quorum (Dragonboat)
  knxvault-2 (id=3) ──┘
         │
    HTTP Service :8200
```

## Step 1 — Build and tag the image

```bash
cd /path/to/knxvault
make container-build
# Or push to your registry:
docker tag knxvault:0.4.5 registry.example.com/knxvault:0.4.5
docker push registry.example.com/knxvault:0.4.5
```

Edit `deployments/k8s/statefulset.yaml` and set `image:` to your tag.

## Step 2 — Generate secrets

Raft requires **master** and a **distinct unseal** key. Pods crash-loop with `unseal key is required when raft is enabled` if unseal is missing.

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_UNSEAL_KEY=$(openssl rand -base64 32)   # must differ from master
export KNXVAULT_ROOT_TOKEN=$(openssl rand -hex 32)
export KNXVAULT_AUDIT_SIGNING_KEY=$(openssl rand -hex 32)

# Sanity: reject accidental identical keys
[ "$KNXVAULT_MASTER_KEY" != "$KNXVAULT_UNSEAL_KEY" ] || { echo "master and unseal must differ"; exit 1; }

echo "Save these securely — master is required for backup restore; unseal for seal/unseal and Raft startup."
```

Edit `deployments/k8s/secret.yaml` (all keys are injected via `envFrom.secretRef`):

- `KNXVAULT_MASTER_KEY` — envelope encryption key (32 bytes, base64)
- `KNXVAULT_UNSEAL_KEY` — **required** with Raft; must differ from master
- `KNXVAULT_ROOT_TOKEN` — bootstrap admin token (rotate after setup)
- `KNXVAULT_AUDIT_SIGNING_KEY` — optional; enables signed audit export heads

Confirm `deployments/k8s/configmap.yaml` contains matching Raft members:

```text
KNXVAULT_RAFT_INITIAL_MEMBERS=1=knxvault-0.knxvault-raft.knxvault.svc.cluster.local:63001,2=knxvault-1.knxvault-raft.knxvault.svc.cluster.local:63001,3=knxvault-2.knxvault-raft.knxvault.svc.cluster.local:63001
```

## Step 3 — Apply manifests

```bash
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
# Optional hardening:
kubectl apply -f deployments/k8s/networkpolicy.yaml
```

Wait for all pods:

```bash
kubectl -n knxvault wait --for=condition=ready pod -l app.kubernetes.io/name=knxvault --timeout=600s
kubectl -n knxvault get pods -o wide
kubectl -n knxvault get pvc
```

## Step 4 — Verify cluster health

```bash
kubectl -n knxvault port-forward svc/knxvault 8200:8200 &
export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=<your-root-token>

curl -s $KNXVAULT_ADDR/health | jq .
curl -s $KNXVAULT_ADDR/ready | jq .
```

On each pod, check Raft state:

```bash
for i in 0 1 2; do
  echo "=== knxvault-$i ==="
  kubectl -n knxvault exec knxvault-$i -- wget -qO- http://localhost:8200/ready 2>/dev/null | jq .
done
```

Expected on `/ready`:

- All pods: `status: ready`, `sealed: false`, `raft_enabled: true`, `raft_ready: true`
- Exactly one pod: `leader: true`

Check Prometheus metrics:

```bash
curl -s $KNXVAULT_ADDR/metrics | grep knxvault_raft_leader
# Exactly one line with value 1 across the cluster (scrape each pod or aggregate in Prometheus)
```

CLI smoke test:

```bash
knxvault-cli doctor --json   # healthy:true, fail:0 (http warn ok until TLS is enabled)
knxvault-cli kv put cluster/bootstrap value=ok
knxvault-cli kv get cluster/bootstrap                 # [REDACTED]
knxvault-cli kv get cluster/bootstrap --show-secrets  # plaintext
```

## Step 5 — Post-deploy hardening

1. **Rotate root token** — create an admin policy and issue a new token; revoke bootstrap token.
2. **Take a backup** — see [Backup and restore](backup-and-restore.md).
3. **Configure RBAC** — see [RBAC policies](rbac-policies.md).
4. **Enable audit forwarding** — see [Audit SIEM forwarding](audit-siem-forwarding.md).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Pod stuck `Pending` | No StorageClass / PVC quota | Check `kubectl describe pvc` |
| CrashLoop: `unseal key is required when raft is enabled` | Missing / equal `KNXVAULT_UNSEAL_KEY` in Secret | Set distinct base64-32 unseal in `secret.yaml` |
| `raft_ready: false` | `INITIAL_MEMBERS` mismatch | Align IDs with pod ordinals +1 |
| Two leaders in metrics | Scraping stale target | Confirm per-pod scrape; only one `leader=1` |
| `KNXVAULT_RAFT_NODE_ID must be > 0` | Raft on without node ID | Use StatefulSet (auto-derive) or set ID explicitly |
| Single-node lab only | Not enough nodes for 3-replica STS | Use [local-dev single-node](local-dev-single-node.md) or [lab E2E](../engineering/lab-e2e-test01.md) |

## Related recipes

- [Local dev single-node](local-dev-single-node.md)
- [Add and remove Raft nodes](raft-add-remove-node.md)
- [Raft failover recovery](raft-failover-recovery.md)
- [Rolling upgrade](rolling-upgrade-ha.md)

## See also

- [Kubernetes deployment](../deploy/kubernetes.md)
- [Dragonboat storage](../storage/dragonboat.md)
- [Raft HA & recovery](../storage/raft-ha-and-recovery.md)