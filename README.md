# KNXVault

Lightweight, production-grade secrets management and PKI built in Go.

## Requirements

- Go 1.25+ (auto-downloaded via `GOTOOLCHAIN=go1.25.11` in the Makefile)
- `golangci-lint` v2, `gosec`, `trivy` (install: `make install-tools`)
- PostgreSQL 15+ (optional; in-memory repos used when unset)
- OpenSSL 3.x (required for PKI operations)
- Docker (optional; for `make docker-build` and Postgres integration tests)

## Quick start

```bash
make all
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_ROOT_TOKEN=dev-root-token
./bin/knxvault
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
make docker-build          # builds knxvault:0.1.0-dev
docker run --rm -p 8200:8200 \
  -e KNXVAULT_MASTER_KEY="$(openssl rand -base64 32)" \
  -e KNXVAULT_ROOT_TOKEN=dev-root-token \
  knxvault:0.1.0-dev
```

## Kubernetes

Raw manifests (no Helm): [`deployments/k8s/`](deployments/k8s/) — see [`docs/deploy/kubernetes.md`](docs/deploy/kubernetes.md).  
Secrets injection: [`docs/deploy/secrets-injection.md`](docs/deploy/secrets-injection.md) and [`deployments/k8s/sidecar-example.yaml`](deployments/k8s/sidecar-example.yaml).

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness |
| GET | `/ready` | Readiness |
| GET | `/metrics` | Prometheus metrics |
| GET | `/openapi.yaml` | OpenAPI spec |
| GET | `/swagger` | Swagger UI |
| POST | `/auth/kubernetes` | K8s SA login (JWT → client token) |
| POST | `/auth/token` | Validate opaque token |
| GET | `/sys/capabilities` | Token capabilities |
| POST | `/pki/root` | Create root CA |
| POST | `/pki/intermediate` | Create intermediate CA |
| POST | `/pki/issue` | Issue leaf certificate (`auto_renew` optional) |
| POST | `/pki/renew` | Renew a tracked leaf certificate |
| POST | `/pki/ocsp/:id` | OCSP responder (DER; no auth) |
| GET | `/pki/ca/:id` | Get CA by ID |
| POST | `/pki/revoke` | Revoke certificate serial |
| GET | `/pki/crl/:id` | Generate CRL |
| POST | `/inject/render` | Render KV secrets for sidecar/init injection |
| POST | `/secrets/kv/*path` | Write secret version |
| GET | `/secrets/kv/*path` | Read latest secret |
| DELETE | `/secrets/kv/*path` | Delete secret path |
| PUT | `/secrets/database/roles/:name` | Configure DB credential role |
| GET | `/secrets/database/roles/:name` | Get DB credential role |
| POST | `/secrets/database/creds/:role` | Generate ephemeral DB credentials |
| POST | `/secrets/database/renew/:lease_id` | Renew lease / rotate TTL |
| PUT | `/secrets/database/revoke/:lease_id` | Revoke lease |
| PUT | `/sys/policies/:name` | Create/update RBAC policy |
| GET | `/sys/policies` | List policies |
| GET | `/sys/policies/:name` | Get policy |
| DELETE | `/sys/policies/:name` | Delete policy |
| PUT | `/sys/roles/:name` | Create/update role binding |
| GET | `/sys/roles/:name` | Get role |
| POST | `/sys/backup` | Export encrypted vault snapshot |
| POST | `/sys/restore` | Restore from encrypted snapshot |
| GET | `/audit/export` | Export audit log with signed chain head |
| POST | `/audit/verify` | Verify audit hash chain |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_HTTP_ADDR` | `:8200` | HTTP listen address |
| `KNXVAULT_LOG_LEVEL` | `info` | Log level |
| `KNXVAULT_VERSION` | `0.1.0-dev` | Version string |
| `KNXVAULT_SHUTDOWN_GRACE` | `10s` | Graceful shutdown timeout |
| `KNXVAULT_DATABASE_URL` | _(empty)_ | PostgreSQL URL (in-memory if unset) |
| `KNXVAULT_AUTO_MIGRATE` | `true` | Apply SQL migrations on startup |
| `KNXVAULT_MASTER_KEY` | _(empty)_ | Base64-encoded 32-byte master key |
| `KNXVAULT_MASTER_KEY_FILE` | _(empty)_ | Path to base64 master key file |
| `KNXVAULT_ROOT_TOKEN` | _(empty)_ | Bootstrap admin token |
| `KNXVAULT_JWT_SECRET` | _(empty)_ | HS256 secret for K8s JWT login |
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
| `KNXVAULT_TRACING_SAMPLE_RATIO` | `1` | Trace sampling ratio (0–1) |

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
make test-integration      # API integration tests (+ Postgres if Docker available)
make gosec                 # security static analysis
make docker-build          # container image
```

Observability: [`docs/metrics.md`](docs/metrics.md)

## Layout

See [`docs/lld.md`](docs/lld.md) §3.1. Progress: [`docs/backlog.md`](docs/backlog.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).