# Secrets injection (W18)

KNXVault supports three injection patterns for Phase 2:

## 1. Render API (sidecar / init container)

`POST /inject/render` fetches KV secrets and returns file and environment payloads.

```bash
curl -s -X POST http://localhost:8200/inject/render \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "secrets": [{"path": "app/db", "file_name": "db.env", "env_name": "DB_PASSWORD"}],
    "format": "both"
  }'
```

Requires the `inject-reader` policy (included in `admin`).

## 2. Sidecar example

See [`deployments/k8s/sidecar-example.yaml`](../../deployments/k8s/sidecar-example.yaml) for a shared `emptyDir` volume populated by a curl sidecar.

## 3. CSI provider scaffolding

[`deployments/csi/k8s-provider.yaml`](../../deployments/csi/k8s-provider.yaml) provides a DaemonSet template for a future Secrets Store CSI provider binary. Wire the provider gRPC service to `internal/inject/csi` when implementing the standalone CSI entrypoint.