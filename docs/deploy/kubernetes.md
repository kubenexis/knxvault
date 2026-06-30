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

The default manifests run **3 replicas** with `KNXVAULT_HA_ENABLED=true`. Leader election uses a `coordination.k8s.io` Lease (`knxvault-leader`). Only the elected leader runs background jobs (lease cleanup, CRL refresh, certificate auto-renewal).

| Resource | Purpose |
|----------|---------|
| `serviceaccount.yaml` | Pod identity for Lease API access |
| `role.yaml` / `rolebinding.yaml` | Grant `leases` get/create/update on `coordination.k8s.io` |

Readiness (`GET /ready`) includes `ha_enabled` and `leader` when HA is active. Prometheus exposes `knxvault_leader` (0/1).

ConfigMap keys for background jobs:

| Variable | Default | Purpose |
|----------|---------|---------|
| `KNXVAULT_JOB_CERT_RENEW_INTERVAL` | `1h` | Leader-only cert renewal sweep |
| `KNXVAULT_RENEW_GRACE` | `72h` | Renew certs expiring within this window |

## Certificate renewal & OCSP

Issue leaf certificates with `"auto_renew": true` to track them in `issued_certificates`. The leader job calls `RenewExpiring` on each tick. Manual renewal: `POST /pki/renew` with `ca_id` and `serial`.

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
| Readiness | `GET /ready` | DB reachable (when configured) |

## Metrics

Prometheus scrape annotations are set on the pod template. See [`docs/metrics.md`](../metrics.md).

## Verify

```bash
kubectl -n knxvault port-forward svc/knxvault 8200:8200
curl -s http://localhost:8200/health
curl -s http://localhost:8200/metrics | head
```