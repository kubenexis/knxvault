# Testing Guide

KNXVault uses a layered test strategy: unit tests alongside packages, in-memory repository fakes, and integration tests including a 3-node Raft suite.

## Unit tests

```bash
make test
# or
go test ./...
```

Tests live next to source files (`*_test.go`). Repository fakes in `internal/repository/memory/` support engine and service tests without Raft.

### Coverage focus areas

| Package | What to test |
|---------|--------------|
| `internal/domain/` | Validation rules |
| `internal/crypto/` | Envelope round-trip, master key loading |
| `internal/engine/` | PKI, KVv2, database credential logic |
| `internal/auth/` | Policy evaluation, token validation |
| `internal/raft/` | State machine commands, snapshot round-trip |
| `internal/api/middleware/` | Auth, rate limit, signing, error mapping |
| `internal/acme/` | SSRF allow-list, account key PEM, mock ACME Issue |

### Coverage gate (≥80%, best effort)

```bash
make test-coverage   # COVERAGE_MIN=80 on operator pure-logic + acme
```

The gate covers `internal/operator/{renew,secretutil,statusutil,reconcileutil,certlogic}` and `internal/acme`. Broader packages (auth, middleware, handlers) are improved best-effort beyond the gate.

Formal audit logs:

- [10-cycle bugfix](../audit/formal-10cycle-bugfix-coverage-2026-07-16.md)
- [5-cycle security auditor (PKI + Go)](../audit/formal-5cycle-security-auditor-2026-07-16.md)
- [3-cycle technical review](../audit/formal-3cycle-tech-review-2026-07-16.md)
- [W52 security audit remediation](../audit/formal-security-remediation-w52-2026-07-16.md)

Security persona skill: `.grok/skills/knxvault-security-auditor/` (`/knxvault-security-auditor`).

## Integration tests

```bash
make test-integration
```

Located in `test/integration/`:

| Suite | Description |
|-------|-------------|
| `api_test.go` | Full HTTP API against in-memory backend |
| `api_raft_test.go` | HTTP API with single-node Raft (`KNXVAULT_RAFT_ENABLED=true`) |
| `raft_test.go` | 3-node Raft cluster: linearizable writes |
| `raft_failover_test.go` | Leader failover: stop leader, verify reads/writes on survivors |
| `e2e_daemon_test.go` | Local `knxvault serve` daemon + `knxvault-cli` over `--addr` (PKI + KV workflow) |
| `w53_e2e_test.go` | W53 residuals: Shamir multi-share unseal, tenant PKI, client-cert login, shamir package smoke |

Integration tests set `KNXVAULT_MASTER_KEY` and `KNXVAULT_ROOT_TOKEN` programmatically. E2E daemon tests (`TestE2E*`) build `knxvault` and `knxvault-cli` once, start `knxvault serve` on an ephemeral port, **unseal** (crypto installs a seal using the unseal key or master-key fallback), and drive the CLI with `KNXVAULT_ADDR` / `--addr`. OpenSSL must be on `PATH` for PKI steps. Raft tests spawn multiple server processes with distinct `KNXVAULT_RAFT_NODE_ID` values. Unit tests that enable Raft via `config.Load()` must also set `KNXVAULT_RAFT_NODE_ID` (> 0) — otherwise validation fails before dependency wiring.

## Static analysis and security gates

Included in `make all`:

```bash
make lint      # golangci-lint v2
make gosec     # gosec static analysis (.gosec.json config)
make licenses  # SPDX allow-list (config/licenses.allow)
make scan      # Trivy vulnerability scan
```

A PR should pass all gates locally before submission.

## Manual testing

For structured HA, security stress, and PoC evaluation exercises, see **[Manual testing strategy](manual-testing-strategy.md)** — includes **MT-01** (network disruption), **MT-02** (rotation latency + SLA), **MT-10** (RBAC/isolation), **MT-11** / **MT-19** (audit export + tamper), and **MT-33** / **MT-36** (emergency seal, token revocation).

Lab single-node Raft E2E on bare metal (`e2e-test01` / `192.168.137.131`):

- **Full suite (recommended):** `bash scripts/lab-full-e2e.sh` or `make lab-full-e2e` — core CLI/API + **post-start unseal** + Vault product profile + operator CRDs + W53 share-split checks → **[lab-full-e2e.md](lab-full-e2e.md)** (last: **44/44 PASS**, 2026-07-16)
- Core-only historical record: **[lab-e2e-test01.md](lab-e2e-test01.md)**
- Operator-only: `bash scripts/lab-operator-e2e.sh`

**Seal note:** Raft lab runs set `KNXVAULT_UNSEAL_KEY` and therefore start sealed. The full lab script unseals before checks; local daemon harness does the same with the master-key fallback.

### Quick smoke (local)

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_ROOT_TOKEN=dev-root-token
./bin/knxvault serve &

export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=dev-root-token
./bin/knxvault-cli health
./bin/knxvault-cli doctor --json
./bin/knxvault-cli kv put test/key value=hello
# Default CLI output redacts values ([REDACTED]); stderr hints to use --show-secrets
./bin/knxvault-cli kv get test/key
./bin/knxvault-cli kv get test/key --show-secrets
```

### Single-node Raft manual test

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_UNSEAL_KEY=$(openssl rand -base64 32)   # required; must differ from master
export KNXVAULT_ROOT_TOKEN=dev-root-token
export KNXVAULT_RAFT_ENABLED=true
export KNXVAULT_RAFT_NODE_ID=1
export KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001
export KNXVAULT_RAFT_DATA_DIR=/tmp/knxvault-raft-test
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001
./bin/knxvault serve
```

## Writing new tests

- Use table-driven tests for validation and error paths
- Mock repositories via `internal/repository/memory` implementations
- For API tests, use `httptest` or the integration harness in `test/integration/`
- Raft state machine changes require snapshot round-trip tests in `internal/raft/`

## Documentation lint

Bare `kv get` examples must document redaction or use `--show-secrets` (see `scripts/check-kv-get-docs.sh`):

```bash
make docs-lint
```

Included in `make all` after `lint`.

## Related documents

- [Manual testing strategy](manual-testing-strategy.md)
- [Development guide](development.md)
- [Contributing](contributing.md)
- [CLI reference](../cli/reference.md) — `kv get` redaction / `--show-secrets`