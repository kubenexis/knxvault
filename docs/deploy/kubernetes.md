# Kubernetes Deployment (raw manifests)

KNXVault ships **raw Kubernetes manifests** in [`deployments/k8s/`](../../deployments/k8s/). Helm is deferred to long-term future (see [`docs/backlog.md`](../backlog.md)).

## Prerequisites

- Kubernetes 1.28+
- Container image built locally or pushed to your registry
- Persistent volumes for Raft data (StatefulSet)

## Build the image

```bash
make docker-build
# or with a registry tag:
docker build -t registry.example.com/knxvault:0.1.0-dev .
```

Update `deployments/k8s/statefulset.yaml` `image:` to match your tag.

## Configure secrets

Edit [`deployments/k8s/secret.yaml`](../../deployments/k8s/secret.yaml):

1. `KNXVAULT_MASTER_KEY` — `openssl rand -base64 32`
2. `KNXVAULT_ROOT_TOKEN` — strong bootstrap token
3. `KNXVAULT_AUDIT_SIGNING_KEY` — optional HMAC key for audit export integrity

PostgreSQL is **deprecated**; migrate existing data with [`knxvault-cli migrate postgres`](../cli/reference.md).

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

The StatefulSet runs **3 replicas** with Dragonboat Raft (`KNXVAULT_RAFT_ENABLED=true`). Node IDs are derived from pod names (`knxvault-0` → node `1`). Background jobs run only on the Raft leader.

| Resource | Purpose |
|----------|---------|
| `statefulset.yaml` | 3-replica Raft cluster with PVC per pod |
| `service-raft.yaml` | Headless Service for stable Raft DNS |
| `service.yaml` | HTTP Service for API traffic |

Readiness (`GET /ready`) includes `raft_enabled`, `raft_ready`, and `leader` when HA is active. Prometheus exposes `knxvault_raft_leader`, `knxvault_raft_term`, and `knxvault_raft_commit_index`.

See [`docs/storage/dragonboat.md`](../storage/dragonboat.md) for Raft configuration details.

## Certificate renewal & OCSP

Issue leaf certificates with `"auto_renew": true` to track them in issued certificates. The Raft leader job calls `RenewExpiring` on each tick. Manual renewal: `POST /pki/renew` with `ca_id` and `serial`.

OCSP is exposed at `POST /pki/ocsp/:ca_id` (no authentication). Send `application/ocsp-request` DER; receive `application/ocsp-response`.

## Secrets injection

Sidecar and init-container patterns use `POST /inject/render` (requires `inject-reader` policy). See [`secrets-injection.md`](secrets-injection.md) and [`deployments/k8s/sidecar-example.yaml`](../../deployments/k8s/sidecar-example.yaml). CSI scaffolding lives in [`deployments/csi/`](../../deployments/csi/).

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
| Readiness | `GET /ready` | Raft leader elected (when enabled) |

## Metrics

Prometheus scrape annotations are set on the pod template. See [`docs/metrics.md`](../metrics.md).

## Verify

```bash
kubectl -n knxvault port-forward svc/knxvault 8200:8200
curl -s http://localhost:8200/health
curl -s http://localhost:8200/ready
curl -s http://localhost:8200/metrics | head
```

## Legacy Deployment manifest

[`deployments/k8s/deployment.yaml`](../../deployments/k8s/deployment.yaml) remains for reference (PostgreSQL + Kubernetes Lease HA). New clusters should use the StatefulSet + Raft manifests above.