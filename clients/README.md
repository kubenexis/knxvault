# KNXVault client SDKs

Official client libraries generated from [`api/openapi.yaml`](../api/openapi.yaml).

| Language | Directory | Generator | Status |
|----------|-----------|-----------|--------|
| Go | [`pkg/client`](../pkg/client/) | Hand-maintained (reference) | **Shipped** |
| Python | `python/knxvault/` | Hand-maintained + `python` generator | **Shipped** |
| Node.js / TypeScript | `typescript/` | Hand-maintained + `typescript-axios` generator | **Shipped** |
| Java | `java/` | Hand-maintained + `java` generator | **Shipped** |
| Rust | `rust/` | Hand-maintained + `rust` generator | **Shipped** |

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
make test-clients              # Go client unit/smoke tests
PYTHONPATH=clients/python python -m unittest tests.clients.test_python
cd clients/rust && cargo test
cd clients/java && mvn -q test
cd clients/typescript && npm install && npm run build
```

Set `KNXVAULT_SMOKE=1` and `KNXVAULT_TOKEN` to run live KV smoke tests against a running server.