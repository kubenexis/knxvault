# Testing Guide

KNXVault uses a layered test strategy: unit tests alongside packages, in-memory repository fakes, and integration tests including a 3-node Raft suite.

## Unit tests

```bash
make test
# or
go test ./...
```

Tests live next to source files (`*_test.go`). Repository fakes in `internal/repository/memory/` support engine and service tests without Raft or PostgreSQL.

### Coverage focus areas

| Package | What to test |
|---------|--------------|
| `internal/domain/` | Validation rules |
| `internal/crypto/` | Envelope round-trip, master key loading |
| `internal/engine/` | PKI, KVv2, database credential logic |
| `internal/auth/` | Policy evaluation, token validation |
| `internal/raft/` | State machine commands, snapshot round-trip |
| `internal/api/middleware/` | Auth, rate limit, signing, error mapping |

## Integration tests

```bash
make test-integration
```

Located in `test/integration/`:

| Suite | Description |
|-------|-------------|
| `api_test.go` | Full HTTP API against in-memory backend |
| `raft_*` | 3-node Raft cluster: linearizable writes, leader failover |

Integration tests set `KNXVAULT_MASTER_KEY` and `KNXVAULT_ROOT_TOKEN` programmatically. Raft tests spawn multiple server processes with distinct `KNXVAULT_RAFT_NODE_ID` values.

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

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_ROOT_TOKEN=dev-root-token
./bin/knxvault &

export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=dev-root-token
./bin/knxvault-cli health
./bin/knxvault-cli kv put test/key value=hello
./bin/knxvault-cli kv get test/key
```

### Single-node Raft manual test

```bash
export KNXVAULT_RAFT_ENABLED=true
export KNXVAULT_RAFT_NODE_ID=1
export KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001
export KNXVAULT_RAFT_DATA_DIR=/tmp/knxvault-raft-test
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001
./bin/knxvault
```

## PostgreSQL integration tests (legacy)

`internal/repository/postgres/integration_test.go` runs when `KNXVAULT_DATABASE_URL` is set. These tests cover the deprecated backend; primary storage tests are in the Raft integration suite.

## Writing new tests

- Use table-driven tests for validation and error paths
- Mock repositories via `internal/repository/memory` implementations
- For API tests, use `httptest` or the integration harness in `test/integration/`
- Raft state machine changes require snapshot round-trip tests in `internal/raft/`

## Related documents

- [Development guide](development.md)
- [Contributing](contributing.md)