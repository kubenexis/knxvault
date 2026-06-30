# KNXVault

Lightweight, production-grade secrets management and PKI built in Go.

## Requirements

- Go 1.25+ (auto-downloaded via `GOTOOLCHAIN=go1.25.11` in the Makefile)
- `golangci-lint` v2, `gosec`, `trivy` (install: `make install-tools`)
- Dragonboat Raft storage (`KNXVAULT_RAFT_ENABLED=true`) for production; in-memory repos used when unset
- OpenSSL 3.x (required for PKI operations)
- Docker (optional; for `make docker-build`)

## Quick start

```bash
make all
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_ROOT_TOKEN=dev-root-token
./bin/knxvault serve
```

API documentation: [http://localhost:8200/swagger](http://localhost:8200/swagger)  
Metrics: [http://localhost:8200/metrics](http://localhost:8200/metrics)

### Example workflow

```bash
# Authenticate (bootstrap root token)
curl -s -X POST http://localhost:8200/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"token":"dev-root-token"}'

# Create a root CA
curl -s -X POST http://localhost:8200/pki/root \
  -H "Authorization: Bearer dev-root-token" \
  -H 'Content-Type: application/json' \
  -d '{"name":"root","common_name":"KNXVault Root","ttl":"8760h"}'

# Write a secret
curl -s -X POST http://localhost:8200/secrets/kv/app/db \
  -H "Authorization: Bearer dev-root-token" \
  -H 'Content-Type: application/json' \
  -d '{"data":{"password":"s3cret"},"options":{"ttl":"24h"}}'

# Read a secret
curl -s http://localhost:8200/secrets/kv/app/db \
  -H "Authorization: Bearer dev-root-token"
```

## Container image

```bash
make docker-build          # builds knxvault:0.4.5
docker run --rm -p 8200:8200 \
  -e KNXVAULT_MASTER_KEY="$(openssl rand -base64 32)" \
  -e KNXVAULT_ROOT_TOKEN=dev-root-token \
  knxvault:0.4.5 serve
```

## Kubernetes

Raw manifests (no Helm): [`deployments/k8s/`](deployments/k8s/) — see [`docs/deploy/kubernetes.md`](docs/deploy/kubernetes.md).  
Secrets injection: [`docs/deploy/secrets-injection.md`](docs/deploy/secrets-injection.md) and [`deployments/k8s/sidecar-example.yaml`](deployments/k8s/sidecar-example.yaml).

## API endpoints

Full catalog: [`docs/api/reference.md`](docs/api/reference.md) · Interactive docs: `/swagger` · OpenAPI: `/openapi.yaml`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness |
| GET | `/ready` | Readiness (Raft leader, seal state) |
| GET | `/metrics` | Prometheus metrics |
| POST | `/auth/kubernetes` | K8s SA login (JWT → client token) |
| POST | `/auth/oidc/:role` | OIDC login |
| POST | `/auth/token` | Validate opaque token |
| POST | `/auth/token/create` | Issue scoped client token |
| POST | `/sys/seal` / `/sys/unseal` | Seal / unseal vault |
| POST | `/sys/rotate-master-key` | Rotate envelope master key |
| POST | `/sys/raft/add-node` / `remove-node` | Dynamic Raft membership |
| POST | `/secrets/kv/*path` | Write KV secret |
| POST | `/sys/backup` / `/sys/restore` | Encrypted snapshot export/import |

## Configuration

Server configuration loads in this order: **defaults → `/etc/knxvault.conf` (when present) → environment variables**. Override the file path with `-c` / `--config` on the root command (e.g. `knxvault -c /path/knxvault.conf serve`).

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_HTTP_ADDR` | `:8200` | HTTP listen address |
| `KNXVAULT_LOG_LEVEL` | `info` | Log level |
| `KNXVAULT_VERSION` | `0.4.5` | Version string (build metadata when unset) |
| `KNXVAULT_SHUTDOWN_GRACE` | `10s` | Graceful shutdown timeout |
| `KNXVAULT_RAFT_ENABLED` | `false` | Enable Dragonboat Raft storage |
| `KNXVAULT_RAFT_NODE_ID` | _(K8s: from pod ordinal)_ | Stable Raft member ID (> 0); see [docs/storage/dragonboat.md](docs/storage/dragonboat.md#raft-node-ids--how-to-choose-and-assign) |
| `KNXVAULT_RAFT_ADDRESS` | `127.0.0.1:63001` | Raft advertise/listen address |
| `KNXVAULT_RAFT_DATA_DIR` | `/var/lib/knxvault/raft` | Raft data directory |
| `KNXVAULT_RAFT_INITIAL_MEMBERS` | _(empty)_ | `id=host:port,...` peer map |
| `KNXVAULT_MASTER_KEY` | _(empty)_ | Base64-encoded 32-byte master key |
| `KNXVAULT_MASTER_KEY_FILE` | _(empty)_ | Path to base64 master key file |
| `KNXVAULT_ROOT_TOKEN` | _(empty)_ | Bootstrap admin token |
| `KNXVAULT_JWT_SECRET` | _(empty)_ | HS256 secret for dev K8s JWT login |
| `KNXVAULT_TOKEN_TTL` | `24h` | Issued client token TTL |
| `KNXVAULT_OPENSSL_BINARY` | `openssl` | OpenSSL executable |
| `KNXVAULT_OPENSSL_TIMEOUT` | `60s` | OpenSSL command timeout |
| `KNXVAULT_HA_ENABLED` | `false` | Enable Kubernetes Lease leader election |
| `KNXVAULT_HA_NAMESPACE` | `knxvault` | Lease namespace |
| `KNXVAULT_HA_LEASE_NAME` | `knxvault-leader` | Lease resource name |
| `KNXVAULT_HA_IDENTITY` | pod hostname | Leader election identity |
| `KNXVAULT_JOB_LEASE_CLEANUP_INTERVAL` | `1m` | Expired lease cleanup interval |
| `KNXVAULT_JOB_CRL_REFRESH_INTERVAL` | `15m` | CRL pre-generation interval |
| `KNXVAULT_JOB_CERT_RENEW_INTERVAL` | `1h` | Auto-renewal background job interval |
| `KNXVAULT_RENEW_GRACE` | `72h` | Renew certs expiring within this window |
| `KNXVAULT_AUDIT_SIGNING_KEY` | _(empty)_ | HMAC key for audit export signatures |
| `KNXVAULT_RATE_LIMIT_ENABLED` | `false` | Enable per-token/IP rate limiting |
| `KNXVAULT_RATE_LIMIT_RPM` | `300` | Requests per minute per client |
| `KNXVAULT_REQUEST_SIGNING_KEY` | _(empty)_ | HMAC key for optional request signing |
| `KNXVAULT_REQUEST_SIGNING_REQUIRED` | `false` | Reject unsigned requests when enabled |
| `KNXVAULT_TRACING_ENABLED` | `false` | Enable OpenTelemetry HTTP tracing |
| `KNXVAULT_OTLP_ENDPOINT` | _(collector default)_ | OTLP HTTP endpoint |
| `KNXVAULT_TRACING_SAMPLE_RATIO` | `0` (effective `1` when tracing enabled) | Trace sampling ratio (0–1) |

Complete reference: [`docs/installation/configuration.md`](docs/installation/configuration.md) · Example file: [`config/knxvault.example.yaml`](config/knxvault.example.yaml)

## CLI

```bash
make build-cli
export KNXVAULT_TOKEN=dev-root-token
./bin/knxvault-cli health
./bin/knxvault-cli kv put app/db password=s3cret
./bin/knxvault-cli backup create -o backup.json
```

Reference: [`docs/cli/reference.md`](docs/cli/reference.md) · Backup: [`docs/deploy/backup-restore.md`](docs/deploy/backup-restore.md) · Tracing: [`docs/observability/tracing.md`](docs/observability/tracing.md)

## Development

```bash
make all                   # fmt, vet, lint, gosec, licenses, scan, test, test-integration, build, build-cli, sbom
make test                  # unit tests only
make test-integration      # API + 3-node Raft integration tests
make gosec                 # security static analysis
make docker-build          # container image
```

Observability: [`docs/metrics.md`](docs/metrics.md)

## Documentation

Full documentation index: [`docs/README.md`](docs/README.md)

| Topic | Guide |
|-------|-------|
| Architecture | [`docs/architecture/hld.md`](docs/architecture/hld.md) |
| Install | [`docs/installation/install.md`](docs/installation/install.md) |
| Kubernetes | [`docs/deploy/kubernetes.md`](docs/deploy/kubernetes.md) |
| Operations | [`docs/operations/day2.md`](docs/operations/day2.md) |
| PKI / TLS | [`docs/operations/pki-administration.md`](docs/operations/pki-administration.md) |
| Development | [`docs/engineering/development.md`](docs/engineering/development.md) |
| Backlog | [`docs/backlog.md`](docs/backlog.md) |

Low-level design: [`docs/lld.md`](docs/lld.md) §3.1.

## License

Apache-2.0 — see [LICENSE](LICENSE).