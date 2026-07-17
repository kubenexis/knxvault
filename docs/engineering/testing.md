# Testing Guide

KNXVault uses a layered test strategy: unit tests alongside packages, integration tests (including local daemon E2E and multi-node Raft), and bare-metal lab E2E on `e2e-test01`.

**Canonical E2E/lab map:** [E2E and lab tests](e2e-and-lab-tests.md) — what each layer covers, multi-share unseal sequence, 53-check lab breakdown, W53 matrix.

## Quick commands

```bash
make test                 # unit tests (go test ./...)
make test-coverage        # ≥80% operator pure-logic + acme gate
make test-integration     # API + Raft + daemon E2E + W53 HTTP
make lab-full-e2e         # bare-metal full suite (SSH root@192.168.137.131)
make all                  # fmt, vet, lint, docs-lint, gosec, licenses, scan, test, test-integration, build, sbom
```

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
| `internal/crypto/shamir/` | GF(2^8) split/combine (multi-share unseal) |
| `internal/engine/` | PKI, KVv2, database credential logic |
| `internal/auth/` | Policy evaluation, token validation, cert login, shared lockout |
| `internal/app/` | Seal/unseal, multi-share `SubmitShare` |
| `internal/raft/` | State machine commands, snapshot round-trip |
| `internal/api/middleware/` | Auth, rate limit, signing, error mapping |
| `internal/acme/` | SSRF allow-list, account key PEM, mock ACME Issue |
| `internal/service/` | Tenant scoping for DB/SSH/PKI |

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
- [W53 residual features + E2E](../audit/formal-w53-residual-features-2026-07-16.md)

Security persona skill: `.grok/skills/knxvault-security-auditor/` (`/knxvault-security-auditor`).

## Integration tests and local E2E

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
| `seal_test.go` | Operational seal blocks writes; full-key unseal |
| `tenant_test.go` | Tenant mode on/off / missing namespace |
| `e2e_daemon_test.go` | Local `knxvault serve` + `knxvault-cli` (PKI + KV workflow) |
| `e2e_harness_test.go` | Binary build, ephemeral port, **auto-unseal** after ready |
| `w53_e2e_test.go` | Shamir multi-share unseal HTTP, tenant PKI, client-cert login, shamir smoke |

### Unseal in local E2E

Crypto wiring always installs a seal (configured unseal key, or **master-key fallback** when `KNXVAULT_UNSEAL_KEY` is unset). Daemon tests call `unsealDaemon` after `/ready` so doctor/PKI/KV succeed.

Multi-share path (`TestE2EMultiShareUnsealHTTP`): threshold 2, offline split, two `{"share":…}` posts — no full key.

Integration tests set `KNXVAULT_MASTER_KEY` and `KNXVAULT_ROOT_TOKEN` programmatically. PKI steps use the native Go backend (no OpenSSL on `PATH`). Raft tests spawn multiple processes with distinct `KNXVAULT_RAFT_NODE_ID` values. Unit tests that enable Raft via `config.Load()` must also set `KNXVAULT_RAFT_NODE_ID` (> 0).

## Static analysis and security gates

Included in `make all`:

```bash
make lint      # golangci-lint v2
make docs-lint # bare kv get examples must document redaction
make gosec     # gosec static analysis (.gosec.json config)
make licenses  # SPDX allow-list (config/licenses.allow)
make scan      # Trivy vulnerability scan
```

A PR should pass all gates locally before submission.

## Lab E2E (bare metal)

Host: **`e2e-test01` / `192.168.137.131`** (SSH as `root`).

| Suite | Command | Last result | Doc |
|-------|---------|-------------|-----|
| **Full (recommended)** | `make lab-full-e2e` | **53/53 PASS** (2026-07-16) | [lab-full-e2e.md](lab-full-e2e.md) |
| Map of all E2E layers | — | — | [e2e-and-lab-tests.md](e2e-and-lab-tests.md) |
| Operator-only | `bash scripts/lab-operator-e2e.sh` | — | script header |
| Core-only historical | — | 20/20 (older) | [lab-e2e-test01.md](lab-e2e-test01.md) |

### Full lab unseal model (current)

The full lab suite opens the data plane with **Shamir multi-share unseal**, not a single full-key post:

1. Offline split: `go run ./scripts/shamir-split -key "$UNSEAL" -n 3 -t 2`
2. Start with `KNXVAULT_UNSEAL_THRESHOLD=2` → sealed
3. Submit share 1 → progress; share 2 → unsealed
4. KV write proves data plane
5. Check section **multishare**: re-seal, alternate share pair (1+3), `generate-unseal-shares` while unsealed

Requires: Go on the **build** host (offline split), OpenSSL, `kubectl` on the lab host, `make build build-cli build-operator`.

## Manual testing

For structured HA, security stress, and PoC evaluation, see **[Manual testing strategy](manual-testing-strategy.md)** — **MT-01** (network disruption), **MT-02** (rotation latency), **MT-10** (RBAC/isolation), **MT-11** / **MT-19** (audit), **MT-33** (emergency seal / multi-share break-glass), **MT-36** (token revocation).

### Quick smoke (local)

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_ROOT_TOKEN=dev-root-token
./build/bin/knxvault serve &
# Process starts sealed (master-key fallback as unseal). Unseal before writes:
curl -s -X POST "http://127.0.0.1:8200/sys/unseal" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$KNXVAULT_MASTER_KEY\"}"

export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=dev-root-token
./build/bin/knxvault-cli health
./build/bin/knxvault-cli doctor --json
./build/bin/knxvault-cli kv put test/key value=hello
./build/bin/knxvault-cli kv get test/key
./build/bin/knxvault-cli kv get test/key --show-secrets
```

### Single-node Raft manual test

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_UNSEAL_KEY=$(openssl rand -base64 32)   # required; must differ from master
export KNXVAULT_UNSEAL_THRESHOLD=1                      # or 2+ for multi-share (see seal recipe)
export KNXVAULT_ROOT_TOKEN=dev-root-token
export KNXVAULT_RAFT_ENABLED=true
export KNXVAULT_RAFT_NODE_ID=1
export KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001
export KNXVAULT_RAFT_DATA_DIR=/tmp/knxvault-raft-test
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001
./build/bin/knxvault serve
# Then POST /sys/unseal with key or shares before data-plane use.
```

Multi-share operator steps: [Seal and unseal](../recipes/seal-and-unseal.md).

## Writing new tests

- Use table-driven tests for validation and error paths
- Mock repositories via `internal/repository/memory` implementations
- For API tests, use `httptest` or the integration harness in `test/integration/`
- Raft state machine changes require snapshot round-trip tests in `internal/raft/`
- Seal/unseal changes: unit tests in `internal/app/`, HTTP in `test/integration/`, and re-run **lab multi-share** when changing share combine or threshold wiring
- Update [e2e-and-lab-tests.md](e2e-and-lab-tests.md) and [lab-full-e2e.md](lab-full-e2e.md) when lab check counts or unseal flow change

## Documentation lint

Bare `kv get` examples must document redaction or use `--show-secrets` (see `scripts/check-kv-get-docs.sh`):

```bash
make docs-lint
```

Included in `make all` after `lint`.

## Related documents

- [E2E and lab test map](e2e-and-lab-tests.md)
- [Lab full E2E](lab-full-e2e.md)
- [Manual testing strategy](manual-testing-strategy.md)
- [Seal and unseal recipe](../recipes/seal-and-unseal.md)
- [Development guide](development.md)
- [Contributing](contributing.md)
- [CLI reference](../cli/reference.md) — `kv get` redaction / `--show-secrets`
