# Kubernetes Deployment (raw manifests)

KNXVault ships **raw Kubernetes manifests** in [`deployments/k8s/`](../../deployments/k8s/). Helm is deferred to long-term future (see [`docs/backlog.md`](../backlog.md)).

## Prerequisites

- Kubernetes 1.28+
- Container image built locally or pushed to your registry
- Persistent volumes for Raft data (StatefulSet)

## Build images

Catalog, matrix, and containerd/`nerdctl` steps: **[Build and deploy images](../operations/build-and-deploy-images.md)**.

```bash
make container-build              # knxvault:VERSION (server + CSI/webhook/ESO binaries)
make k8s-operator-build     # knxvault-operator:VERSION (optional cert automation)
# tag/push to registry; set image: on StatefulSet and operator Deployment
```

## Configure secrets

Edit [`deployments/k8s/secret.yaml`](../../deployments/k8s/secret.yaml) before apply. The StatefulSet injects **all** keys via `envFrom.secretRef`.

| Key | Required | How to generate | Notes |
|-----|----------|-----------------|-------|
| `KNXVAULT_MASTER_KEY` | **Yes** | `openssl rand -base64 32` | Envelope encryption (DEK wrapping). Never commit real values. |
| `KNXVAULT_UNSEAL_KEY` | **Yes** (Raft STS) | `openssl rand -base64 32` | **Must differ from master.** Startup fails if unset or equal: `unseal key is required when raft is enabled`. Used for seal/unseal, not envelope crypto. |
| `KNXVAULT_ROOT_TOKEN` | **Yes** (bootstrap) | strong random token | Rotate after scoped policies exist. |
| `KNXVAULT_AUDIT_SIGNING_KEY` | Recommended | `openssl rand -base64 32` | Tamper-evident audit export HMAC. |

```bash
# Example (do not paste into git — set in a private Secret / sealed-secrets / external secrets)
openssl rand -base64 32   # master
openssl rand -base64 32   # unseal (run again; must not match master)
```

> **Topology:** Production HA is a **3-replica** StatefulSet. A single-node cluster cannot provide Raft quorum for failover tests. For single-host smoke, use bare-metal/Docker single-node Raft ([install guide](../installation/install.md), [lab E2E](../engineering/lab-e2e-test01.md)).

> **Note:** `deployments/k8s/legacy/deployment.yaml` is deprecated (single Deployment without Raft). Use the StatefulSet flow below for production.

## Deploy (3-node Raft)

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
```

The StatefulSet runs **3 replicas** with Dragonboat Raft (`KNXVAULT_RAFT_ENABLED=true`). Node IDs are **derived** from pod names when `KNXVAULT_RAFT_NODE_ID` is unset: `knxvault-0` → `1`, `knxvault-1` → `2`, `knxvault-2` → `3`. These must match the IDs in `KNXVAULT_RAFT_INITIAL_MEMBERS` in the ConfigMap. See [Raft node IDs](../storage/dragonboat.md#raft-node-ids--how-to-choose-and-assign). Background jobs run only on the Raft leader.

| Resource | Purpose |
|----------|---------|
| `statefulset.yaml` | 3-replica Raft cluster with PVC per pod |
| `service-raft.yaml` | Headless Service for stable Raft DNS |
| `service.yaml` | HTTP Service for API traffic |

Readiness (`GET /ready`) includes production fields when HA is active:

| Field | Operator meaning |
|-------|------------------|
| `status` | `ready` when the pod can accept traffic |
| `sealed` | Must be `false` for writes |
| `raft_enabled` / `raft_ready` | Raft configured and cluster usable |
| `leader` | This pod is the Raft leader (background jobs run here) |

Prometheus exposes `knxvault_raft_leader`, `knxvault_raft_term`, and `knxvault_raft_commit_index`.

See [`docs/storage/dragonboat.md`](../storage/dragonboat.md) for Raft configuration details.

## Certificate renewal & OCSP

Issue leaf certificates with `"auto_renew": true` to track them in issued certificates. The Raft leader job calls `RenewExpiring` on each tick. Manual renewal: `POST /pki/renew` with `ca_id` and `serial`.

OCSP is exposed at `POST /pki/ocsp/:ca_id` (no authentication). Send `application/ocsp-request` DER; receive `application/ocsp-response`.

## Secrets injection

**Secrets delivery:** use the [Secrets Store CSI Driver](csi-install.md) integration first (`deployments/csi/`). Optional [mutating webhook](../../deployments/k8s/webhook/) injects CSI volumes from pod annotations. Sidecar/init fallbacks use `POST /inject/render` — see [`secrets-injection.md`](secrets-injection.md) and [`deployments/k8s/sidecar-example.yaml`](../../deployments/k8s/sidecar-example.yaml).

## Rate limiting & request signing

Optional hardening on secured routes (see ConfigMap / Secret):

| Variable | Default | Purpose |
|----------|---------|---------|
| `KNXVAULT_RATE_LIMIT_ENABLED` | `false` | Per-token/IP token-bucket limiter |
| `KNXVAULT_RATE_LIMIT_RPM` | `300` | Requests per minute |
| `KNXVAULT_REQUEST_SIGNING_KEY` | _(Secret)_ | HMAC key for `X-KNX-Signature` |
| `KNXVAULT_REQUEST_SIGNING_REQUIRED` | `false` | Reject unsigned requests |

## Probes

| Probe | Path | Purpose |
|-------|------|---------|
| Liveness | `GET /health` | Process is alive |
| Readiness | `GET /ready` | Unsealed; Raft ready / leader elected when HA is enabled |

## Metrics

Prometheus scrape annotations are set on the pod template. See [`docs/metrics.md`](../metrics.md).

## Verify

```bash
kubectl -n knxvault port-forward svc/knxvault 8200:8200
export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=<bootstrap-root-token>

curl -s "$KNXVAULT_ADDR/health"   # healthy
curl -s "$KNXVAULT_ADDR/ready"    # ready, sealed:false, raft_ready:true
# Prefer doctor when the CLI is available (host or debug pod):
# knxvault-cli doctor --json   # healthy:true, fail:0
# Expect a warn if traffic is plain HTTP — terminate TLS at ingress in production.

curl -s "$KNXVAULT_ADDR/metrics" | head -n 5
```

Also confirm pods are not crash-looping on missing unseal (check logs for `unseal key is required when raft is enabled`).

## Legacy Deployment manifest

[`deployments/k8s/deployment.yaml`](../../deployments/k8s/deployment.yaml) remains for reference (single-replica Deployment without Raft). New clusters should use the StatefulSet + Raft manifests above.