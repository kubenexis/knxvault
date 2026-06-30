# KNXVault client SDKs

Official client libraries generated from [`api/openapi.yaml`](../api/openapi.yaml).

| Language | Directory | Generator | Status |
|----------|-----------|-----------|--------|
| Go | [`pkg/client`](../pkg/client/) | Hand-maintained (reference) | **Shipped** |
| Python | `python/knxvault/` | `python` | W40-04 |
| Node.js / TypeScript | `typescript/` | `typescript-axios` | W40-05 |
| Java | `java/` | `java` | W40-06 |
| Rust | `rust/` | `rust` | W40-07 |

## Generate

Requires [Docker](https://www.docker.com/) (runs `openapitools/openapi-generator-cli`):

```bash
make generate-clients
```

This refreshes all language trees under `clients/`. Commit generated sources with API changes.

## Authentication

All SDKs use bearer tokens from:

- `KNXVAULT_TOKEN` environment variable
- `POST /auth/kubernetes` for in-cluster ServiceAccount JWT exchange
- `POST /auth/token` for existing token validation

See [Kubernetes-native integrations](../docs/integration/kubernetes-native.md).

## Smoke tests

```bash
make test-clients   # after generate-clients
```