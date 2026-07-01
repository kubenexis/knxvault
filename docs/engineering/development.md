# Development Guide

Local setup and workflow for contributing to KNXVault.

## Prerequisites

```bash
# Go 1.26+ (auto-downloaded via Makefile)
go version

# Optional CI tools
make install-tools   # golangci-lint v2, gosec, trivy
```

OpenSSL 3.x must be on `PATH` for PKI tests.

## Clone and build

```bash
git clone https://github.com/your-org/knxvault.git
cd knxvault

make all          # fmt, vet, lint, gosec, licenses, scan, test, integration, build
make build        # binary only
make build-cli      # knxvault-cli
make build-csi      # knxvault-csi (Secrets Store provider)
make build-webhook  # knxvault-webhook (CSI volume injection)
```

Artifacts:

| Output | Path |
|--------|------|
| Server binary | `bin/knxvault` |
| CLI binary | `bin/knxvault-cli` |
| SBOM | `sbom.json`, `sbom-binary.json` |

## Run locally

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_ROOT_TOKEN=dev-root-token
./bin/knxvault serve
```

Swagger: http://localhost:8200/swagger

## Project layout

```
cmd/knxvault/           Server entrypoint
cmd/knxvault-cli/       Cobra CLI
internal/
  api/                  HTTP handlers, middleware, DTOs
  app/                  Dependency injection / bootstrap
  auth/                 Token auth, RBAC evaluator
  audit/                Hash-chained audit service
  backup/               Snapshot export/import
  config/               YAML file + environment configuration
  crypto/               Master key, envelope crypto, OpenSSL
  domain/               Pure domain models
  engine/               PKI, KVv2, database engines
  inject/               Secrets injection + CSI provider (`knxvault-csi`)
  raft/                 Dragonboat NodeHost + state machine
  repository/           Dragonboat, memory
  service/              Orchestration layer
pkg/client/             Public Go HTTP client
api/openapi.yaml        OpenAPI 3.1 specification
test/integration/       API and 3-node Raft tests
deployments/k8s/        Kubernetes manifests
docs/                   Documentation (this tree)
```

See [LLD §3.1](../lld.md) for the full directory specification.

## Common make targets

| Target | Purpose |
|--------|---------|
| `make fmt` | `gofmt` + `goimports` |
| `make vet` | `go vet` |
| `make lint` | golangci-lint v2 |
| `make test` | Unit tests |
| `make test-integration` | API + Raft integration tests |
| `make gosec` | Security static analysis |
| `make licenses` | SPDX allow-list check |
| `make scan` | Trivy vulnerability scan |
| `make docker-build` | Container image |

## Adding a feature

1. **Domain** — add or extend types in `internal/domain/`
2. **Raft command** — if persisted, add op to `internal/raft/commands.go` and state machine handler
3. **Repository** — implement interface in `internal/repository/dragonboat/`
4. **Engine / service** — business logic in `internal/engine/` and `internal/service/`
5. **API** — handler + DTO in `internal/api/`, update `api/openapi.yaml`
6. **Tests** — unit tests alongside code; integration test in `test/integration/`
7. **Docs** — update relevant guide in `docs/`

## CSI validation (optional)

Requires Docker and `kind` on `PATH`:

```bash
scripts/test-csi-kind.sh   # installs CSI driver + provider RBAC (W39-07 partial)
make test-integration      # includes test/integration/csi_test.go when Docker available
```

Full end-to-end KV mount assertion is tracked in backlog **W39-07**.

## Architecture decisions

Significant design changes require an ADR in [`docs/adr/`](../adr/README.md).

## Related documents

- [Testing guide](testing.md)
- [Contributing](contributing.md)
- [Dragonboat storage](../storage/dragonboat.md)