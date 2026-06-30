# Kubernetes Deployment (raw manifests)

KNXVault Phase 1 ships **raw Kubernetes manifests** in [`deployments/k8s/`](../../deployments/k8s/). Helm is deferred to long-term future (see [`docs/backlog.md`](../backlog.md)).

## Prerequisites

- Kubernetes 1.28+
- PostgreSQL 15+ reachable from the cluster
- Container image built locally or pushed to your registry

## Build the image

```bash
make docker-build
# or with a registry tag:
docker build -t registry.example.com/knxvault:0.1.0-dev .
```

Update `deployments/k8s/deployment.yaml` `image:` to match your tag.

## Configure secrets

Edit [`deployments/k8s/secret.yaml`](../../deployments/k8s/secret.yaml):

1. `KNXVAULT_MASTER_KEY` — `openssl rand -base64 32`
2. `KNXVAULT_ROOT_TOKEN` — strong bootstrap token
3. `KNXVAULT_DATABASE_URL` — PostgreSQL DSN
4. `KNXVAULT_AUDIT_SIGNING_KEY` — optional HMAC key for audit export integrity

## Deploy

```bash
kubectl apply -f deployments/k8s/namespace.yaml
kubectl apply -f deployments/k8s/serviceaccount.yaml
kubectl apply -f deployments/k8s/role.yaml
kubectl apply -f deployments/k8s/rolebinding.yaml
kubectl apply -f deployments/k8s/configmap.yaml
kubectl apply -f deployments/k8s/secret.yaml
kubectl apply -f deployments/k8s/deployment.yaml
kubectl apply -f deployments/k8s/service.yaml
```

## High availability (Phase 2)

The default manifests run **3 replicas** with `KNXVAULT_HA_ENABLED=true`. Leader election uses a `coordination.k8s.io` Lease (`knxvault-leader`). Only the elected leader runs background jobs (lease cleanup, CRL refresh).

| Resource | Purpose |
|----------|---------|
| `serviceaccount.yaml` | Pod identity for Lease API access |
| `role.yaml` / `rolebinding.yaml` | Grant `leases` get/create/update on `coordination.k8s.io` |

Readiness (`GET /ready`) includes `ha_enabled` and `leader` when HA is active. Prometheus exposes `knxvault_leader` (0/1).

## Probes

| Probe | Path | Purpose |
|-------|------|---------|
| Liveness | `GET /health` | Process is alive |
| Readiness | `GET /ready` | DB reachable (when configured) |

## Metrics

Prometheus scrape annotations are set on the pod template. See [`docs/metrics.md`](../metrics.md).

## Verify

```bash
kubectl -n knxvault port-forward svc/knxvault 8200:8200
curl -s http://localhost:8200/health
curl -s http://localhost:8200/metrics | head
```