# Integration Overview

How to connect applications, Kubernetes workloads, and CI/CD pipelines to KNXVault.

## Integration patterns

| Pattern | Auth | Use case |
|---------|------|----------|
| **Direct REST API** | Bearer token | Scripts, services, operators |
| **Go client SDK** | Bearer token | Go applications (`pkg/client`) |
| **CLI** | Bearer token | Human operators, cron jobs |
| **K8s ServiceAccount JWT** | `POST /auth/kubernetes` | In-cluster workloads |
| **Sidecar / init injection** | Scoped token | File/env secret delivery |
| **CSI provider** | Scoped token | Volume-mounted secrets (scaffolding) |

## Kubernetes ServiceAccount authentication

1. Configure `KNXVAULT_JWT_SECRET` on the KNXVault server (HS256).
2. Create a policy and role binding the ServiceAccount:

```json
{
  "policies": ["app-reader"],
  "bound_service_account_names": ["my-app"],
  "bound_service_account_namespaces": ["production"]
}
```

3. From the pod, exchange the projected SA token:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -s -X POST http://knxvault:8200/auth/kubernetes \
  -H 'Content-Type: application/json' \
  -d "{\"jwt\":\"$TOKEN\",\"role\":\"app-sa\"}"
```

Use the returned client token for subsequent API calls.

## Secrets injection

### Render API

`POST /inject/render` returns file contents and environment variables for configured secret paths. Requires the `inject-reader` capability.

```json
{
  "secrets": [
    {"path": "app/db", "file_name": "db.env", "env_name": "DB_PASSWORD"}
  ],
  "format": "both"
}
```

### Sidecar example

[`deployments/k8s/sidecar-example.yaml`](../../deployments/k8s/sidecar-example.yaml) demonstrates an `emptyDir` volume populated by a curl sidecar.

### CSI provider

Scaffolding in [`deployments/csi/`](../../deployments/csi/) and `internal/inject/csi/`. A standalone CSI binary is not yet shipped — wire the gRPC provider when implementing Phase 4 operator work.

## Go client SDK

```go
import "github.com/knxvault/knxvault/pkg/client"

c := client.New("http://knxvault:8200", client.WithToken(os.Getenv("KNXVAULT_TOKEN")))
health, err := c.Health(ctx)
```

The CLI (`knxvault-cli`) uses the same client package. See [CLI reference](../cli/reference.md).

## CI/CD examples

### GitHub Actions

```yaml
- name: Fetch secret
  env:
    KNXVAULT_ADDR: https://knxvault.internal:8200
    KNXVAULT_TOKEN: ${{ secrets.KNXVAULT_CI_TOKEN }}
  run: |
    curl -sf "$KNXVAULT_ADDR/secrets/kv/ci/deploy-key" \
      -H "Authorization: Bearer $KNXVAULT_TOKEN" \
      | jq -r '.data.data.private_key' > deploy-key.pem
```

### GitLab CI

Store `KNXVAULT_TOKEN` as a masked CI variable. Use the same curl pattern or the CLI in a job image that includes `knxvault-cli`.

## PKI integration

| Endpoint | Purpose |
|----------|---------|
| `POST /pki/issue` | Issue leaf certificates |
| `POST /pki/renew` | Manual renewal |
| `GET /pki/crl/:id` | Fetch PEM CRL |
| `POST /pki/ocsp/:id` | OCSP responder (no auth) |

Ingress controllers and service meshes can consume issued certificates directly or via the injection API.

## Terraform provider

Deferred to long-term future. Until a provider exists, use the REST API, CLI, or a `local-exec` provisioner with `knxvault-cli`.

## Observability integration

| System | Integration |
|--------|-------------|
| Prometheus | Scrape `GET /metrics` |
| Grafana | Import [`knxvault-overview.json`](../../deployments/grafana/knxvault-overview.json) |
| OpenTelemetry | Set `KNXVAULT_TRACING_ENABLED=true` — see [tracing guide](../observability/tracing.md) |

## Related documents

- [Getting started](../user/getting-started.md)
- [Kubernetes deployment](../deploy/kubernetes.md)
- [API reference](../api/reference.md)