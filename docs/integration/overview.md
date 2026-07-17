<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Integration Overview

How to connect applications, Kubernetes workloads, and CI/CD pipelines to KNXVault.

For the full Kubernetes-native surface (CSI, ESO, cert-manager, webhook, SDKs), see **[Kubernetes-native integrations](kubernetes-native.md)**.

## Integration patterns

| Pattern | Auth | Use case |
|---------|------|----------|
| **Secrets Store CSI Driver** | Pod SA → TokenReview | **Primary** — volume-mounted secrets (**shipped**: `knxvault-csi`) |
| **External Secrets Operator** | Controller SA | Sync to native `Secret` when needed (**shipped**: `knxvault-eso`) |
| **cert-manager Issuer** | Controller SA | TLS / PKI automation (**shipped**: Vault API shim) |
| **K8s ServiceAccount JWT** | `POST /auth/kubernetes` | In-cluster API access (**shipped**: TokenReview) |
| **Mutating webhook** | — | Optional CSI volume injection (**shipped**: `knxvault-webhook`) |
| **SDKs** (Go, Python, Java, Rust, Node) | Bearer / K8s auth | Application integrations (**Go shipped**; others W40-04–07) |
| **Direct REST API** | Bearer token | Scripts, services, operators |
| **CLI** | Bearer token | Human operators, cron jobs |
| **Sidecar / init injection** | Scoped token | Fallback when CSI unavailable |

## Kubernetes ServiceAccount authentication

**Production:** in-cluster **TokenReview** (automatic when KNXVault runs on Kubernetes). **Dev-only:** `KNXVAULT_JWT_SECRET` (HS256) or `KNXVAULT_K8S_AUTH_INSECURE=true`.

1. Create a policy and role binding the ServiceAccount:

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

## Secrets injection (Kubernetes)

### Secrets Store CSI Driver (recommended)

KNXVault is designed as a **Kubernetes-native** secrets platform. The first-class integration is the [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/) with a dedicated `knxvault` provider:

1. Install the upstream CSI driver in the cluster.
2. Deploy the KNXVault provider DaemonSet ([`deployments/csi/`](../../deployments/csi/)).
3. Create a `SecretProviderClass` referencing KV paths and a bound `Role`.
4. Mount the CSI volume in application pods — secrets appear as files under the mount path.

Pod identity uses `ServiceAccount` TokenReview (no long-lived vault token in the provider). Rotation (**W39-05**) and optional `secretObjects` sync to native Kubernetes `Secret` (**W39-06**) are **shipped**. See [Secrets injection](../deploy/secrets-injection.md) and [CSI install](../deploy/csi-install.md).

### Render API (fallback)

`POST /inject/render` returns file contents and environment variables for sidecar/init patterns. Requires the `inject-reader` capability.

```json
{
  "secrets": [
    {"path": "app/db", "file_name": "db.env", "env_name": "DB_PASSWORD"}
  ],
  "format": "both"
}
```

[`deployments/k8s/sidecar-example.yaml`](../../deployments/k8s/sidecar-example.yaml) demonstrates the curl sidecar pattern.

## Client SDKs

| Language | Package | Status |
|----------|---------|--------|
| Go | `pkg/client` | Shipped |
| Python, TypeScript, Java, Rust | `clients/*` | `make generate-clients` (W40-03–07) |

```go
import "github.com/kubenexis/knxvault/pkg/client"

c := client.New("http://knxvault:8200", os.Getenv("KNXVAULT_TOKEN"))
health, err := c.Health(ctx)
```

The CLI (`knxvault-cli`) uses the same client package. See [clients/README.md](../../clients/README.md) and [CLI reference](../cli/reference.md).

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

## Dynamic database credentials

KNXVault runs in **client** execution mode: it returns SQL `creation_statements` and ephemeral credentials; your executor connects with admin creds from KV or K8s Secrets. See [Database credentials](../deploy/database-credentials.md).

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