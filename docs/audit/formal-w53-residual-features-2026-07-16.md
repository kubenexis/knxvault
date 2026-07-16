# W53 — Residual security features (2026-07-16)

Implements the five residual items from the complete security audit that were previously deferred.

## Features delivered

### 1. Multi-tenant isolation (non-KV) — W32-04

- `DatabaseService`, `SSHService`, and `PKIService` honor `tenantMode` via `scopeResourceName`.
- Role/CA names are prefixed with `tenant-ns/` when `KNXVAULT_TENANT_MODE=true` and `X-KNX-Namespace` / SA namespace is set.
- Inject continues to use `SecretsService` reader (already tenant-scoped for KV paths).

### 2. Multi-share unseal (Shamir)

- Package `internal/crypto/shamir` — GF(2^8) split/combine.
- `SealState.SubmitShare` + `SetUnsealThreshold` (`KNXVAULT_UNSEAL_THRESHOLD`).
- `POST /sys/unseal` accepts `{"share":"<base64>"}` (progress in response) or `{"key":"<base64>"}` (full key).
- `POST /sys/generate-unseal-shares` (admin, `sys/seal` write) splits a key offline-style for distribution.

### 3. AppRole Raft replication

- `AppRoleStore.AttachRaftBackend(secretRepo, crypto)` stores encrypted AppRole JSON at `sys/internal/approles`.
- Register/Delete still write local file when configured **and** write through to SecretRepository (Dragonboat when Raft enabled).
- Load on attach + in-memory auth path.

### 4. Client-cert API login — W34-02

- `POST /auth/cert` with mTLS peer certificate.
- Maps CN (or first DNS SAN) to role policies via RoleResolver; issues opaque client token.

### 5. Cluster-shared rate-limit / lockout

- `SharedLockoutTracker` and `SharedRateLimiter` use `cache.Store` (Valkey when `KNXVAULT_VALKEY_CACHE_URL` set).
- Falls back to process-local maps when Valkey is unavailable.
- Wired in `deps.go` for auth lockout and global secured rate limit.

## Config

| Env | Purpose |
|-----|---------|
| `KNXVAULT_TENANT_MODE` | Enable tenant scoping for KV + DB/SSH/PKI |
| `KNXVAULT_UNSEAL_THRESHOLD` | Shamir t (default 1 = single key) |
| `KNXVAULT_VALKEY_CACHE_URL` | Shared cache for rate limit + lockout (+ KV cache) |

## Residuals still not full product

- Lease IDs not tenant-prefixed (cross-tenant renew if lease ID leaked).
- AppRole Raft requires secret path write permission on all nodes’ engines; follower auth may lag until reload (no push notify).
- Client-cert login does not re-validate chain against a dedicated trust store beyond TLS handshake.
- Shared counters use get/set not atomic INCR (best-effort under contention).

## Verify

```bash
go test ./internal/crypto/shamir/ ./internal/auth/ ./internal/app/ ./internal/service/ -count=1
make test-coverage
go test ./... -count=1
make test-integration   # includes TestE2E* + TestE2EMultiShareUnsealHTTP / tenant / cert
make lab-full-e2e       # bare-metal Raft: start sealed → t-of-n shares → data plane (53 checks)
```

## E2E results (2026-07-16)

| Suite | Result | Notes |
|-------|--------|-------|
| `make test-integration` | **PASS** | Daemon CLI auto-unseal; W53 HTTP multi-share, tenant PKI, cert login |
| `make lab-full-e2e` (`192.168.137.131`) | **PASS 53/53** | **Start sealed → offline 3 shares / threshold 2 → data plane**; re-seal + shares 1+3; generate-unseal-shares; vaultcompat; operator; multi-issuer |

Canonical map: [e2e-and-lab-tests.md](../engineering/e2e-and-lab-tests.md).  
Lab record: [lab-full-e2e.md](../engineering/lab-full-e2e.md).  
Offline split: `scripts/shamir-split/main.go`. Recipe: [seal-and-unseal.md](../recipes/seal-and-unseal.md).
