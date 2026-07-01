# KNXVault Backlog

Actionable backlog derived from [`docs/lld.md`](lld.md). Items are **topologically sorted by dependency** — implement in listed order within each phase.

**Current focus:** [**Tier P — Prospect POC immediate**](#tier-p--prospect-poc-immediate-july-2026-enterprise-memorandum) (**supersedes all other tiers** until prospect exit criteria met). Then remaining **W36** (B–E) → [Tier H](#tier-h--kubernetes-ecosystem-eso-cert-manager-sdks) → [Tier I](#tier-i--enterprise-security--compliance-v10v12) remainder. **Tier 0, Tier A, Tier F (except W38-15), Tier G, webhook** are **shipped**. **Helm, Terraform, AWS/GCP/Azure KMS** → [long-term](#long-term-future) (LT-*); prospect near-term master key = sealed Secrets per [ADR-0006](adr/0006-seal-unseal-strategies.md).

**Legend**

| Field | Meaning |
|-------|---------|
| **ID** | `W#-##` = work item (dependency order within phase) |
| **Effort** | S (< 1 day) · M (1–3 days) · L (3–7 days) · XL (> 1 week) |
| **Area** | ci · crypto · storage · api · auth · k8s · docs · security |
| **Depends on** | Prior backlog IDs that must be complete first |

## Storage backend (architecture pivot)

**Storage backend:** [Dragonboat](https://github.com/lni/dragonboat) — a multi-group Raft consensus library in Go. Vault state (CAs, secrets, audit, RBAC, leases, revocations, issued certs) is replicated through a **Raft state machine**.

| Aspect | Implementation |
|--------|----------------|
| Persistence | Raft log + Pebble (default Dragonboat WAL) + state-machine snapshots |
| HA / consistency | Built-in Raft quorum; leader derived from Raft role |
| Dev / single-node | In-memory repos when Raft disabled, or single-node Raft cluster |
| Backup | Dragonboat snapshots + encrypted export API |

Phases 1–2 below cover application-layer work (engines, API, auth). **Phase 3** delivered the Dragonboat storage and HA substrate; repository interfaces (`internal/repository/interfaces.go`) are implemented in `internal/repository/dragonboat/`.

---

## Tier P — Prospect POC immediate (July 2026 enterprise memorandum)

**Trigger:** Regulated prospect requires POC authorization; memorandum blocks sign-off while OpenSSL subprocess wraps core PKI, plaintext bootstrap keys lack SoD, and memory hardening gaps remain.

**Exit criteria (prospect POC gate):** ✅ P0 docs shipped · ✅ **W41-01** + **W41-02** + **W41-13** · ✅ **W41-05** Shamir · ✅ **W41-09** native PKI · ✅ **W41-06** cascade revoke · compensating-controls checklist signed · `make all` + integration tests green.

**Already satisfied (no Tier P implementation):**

| Memorandum concern | Status | Evidence |
|--------------------|--------|----------|
| Q3 — OpenSSL injection / SafeExec | ✅ Shipped | **W38-11** fuzz, `internal/crypto/openssl/wrapper.go`, circuit breaker **W38-17** |
| Q5 — K8s asymmetric token validation | ✅ Shipped | **W36-02** TokenReview; HS256 dev-only blocked with Raft |
| §5 — `readOnlyRootFilesystem`, non-root, cap drop | ✅ Shipped | `deployments/k8s/statefulset.yaml` |
| Envelope encryption (not OpenSSL) | ✅ Shipped | **W3-02**, [ADR-0003](adr/0003-envelope-encryption.md) |
| Dedicated unseal ≠ master key | ✅ Shipped | **W36-24**, `internal/config/security.go` |

**Deferred with documented compensating controls (prospect waiver):**

| Concern | Workaround | Backlog |
|---------|------------|---------|
| Q2 — Cloud KMS auto-unseal | Sealed Secrets / ESO for `KNXVAULT_MASTER_KEY` | **LT-14**, **LT-15** (long-term) |
| §2.D — External DB (Aurora/Consul) | Dragonboat intentional | **LT-13** non-goal |
| Q1 — Full distroless (no OpenSSL binary) | After native PKI parity | **W41-10** (follows **W41-09**) |

### Tier P — implementation sequence

Implement **top to bottom**. Full specs remain in linked IDs (Tier I / Phase 5); Tier P is the **priority overlay** only.

| Priority | ID | Memo § / Q | Title | Area | Effort | Depends on | Target | Notes |
|----------|-----|------------|-------|------|--------|------------|--------|-------|
| ~~**P0**~~ | ~~**W41-12**~~ | §5 air-gap | ~~Air-gap OpenSSL CVE patching runbook~~ | docs | S | W9-01 | Week 1 | Done — `docs/operations/runbooks/air-gap-image-patching.md` |
| ~~**P0**~~ | ~~**W41-15**~~ | Q1–Q6 | ~~Enterprise memorandum traceability matrix~~ | docs | S | W38-19 | Week 1 | Done — `docs/product/enterprise-memorandum-matrix.md` |
| ~~**P1**~~ | ~~**W41-01**~~ | Q6 | ~~Memory lock (`mlock`) for master and unseal keys~~ | security | M | W36-24 | Week 2–3 | Done — `internal/crypto/memlock/`, wired in loader + seal |
| ~~**P1**~~ | ~~**W41-02**~~ | Q6 | ~~Universal sensitive-buffer lifecycle audit~~ | security | M | W41-01 | Week 3–4 | Done — `internal/crypto/sensitive/`, `make audit-sensitive` |
| ~~**P1**~~ | ~~**W41-13**~~ | §2.A, §5 | ~~Seccomp profile for OpenSSL child processes~~ | security | M | W3-03 | Week 4 | Done — `deployments/k8s/seccomp-openssl.json` |
| ~~**P2**~~ | ~~**W41-05**~~ | Q4 | ~~Shamir threshold unseal (unseal key only)~~ | security | L | W41-01 | Week 5–7 | Done — `internal/crypto/shamir/`, progressive `POST /sys/unseal` |
| ~~**P2**~~ | ~~**W31-01**~~ | Q1 | ~~OpenSSL engine / PKI backend abstraction~~ | crypto | M | W3-03 | Week 5–6 | Done — `internal/crypto/pki/backend.go` |
| ~~**P2**~~ | ~~**W41-08**~~ | Q1 | ~~Go-native `crypto/x509` read and verify fast path~~ | crypto | M | W31-01 | Week 6–7 | Done — `internal/crypto/x509native/reader.go` |
| ~~**P2**~~ | ~~**W38-15**~~ | §2.D TLS | ~~API TLS bootstrap from vault PKI~~ | crypto | M | W37-01 | Week 5–6 | Done — `POST /sys/tls/issue-listener` |
| ~~**P2**~~ | ~~**W41-07**~~ | §2.D OIDC | ~~OIDC group and claim → policy mapping~~ | auth | M | W37-02 | Week 6–7 | Done — `internal/auth/claimmapping.go` |
| ~~**P3**~~ | ~~**W41-09**~~ | Q1 | ~~Go-native full PKI issuance engine~~ | crypto | XL | W41-08 | Week 8–12 | Done — `internal/crypto/x509native/issuer.go` |
| ~~**P3**~~ | ~~**W41-10**~~ | Q1 | ~~OpenSSL subprocess optional mode~~ | crypto | M | W41-09 | Week 12+ | Done — `KNXVAULT_PKI_BACKEND=native`, `Dockerfile.distroless` |
| ~~**P3**~~ | ~~**W41-06**~~ | §2.D tokens | ~~Hierarchical tokens & cascade revocation~~ | auth | L | W36-13 | Week 8–10 | Done — `ParentID`, cascade revoke, metrics |
| ~~—~~ | ~~**W41-14**~~ | Q2 + Q4 | ~~Dual-mode seal (KMS + Shamir)~~ | security | M | W41-05, LT-14 | Post-prospect | Done (stub) — `internal/crypto/autounseal/`, **LT-14** for cloud KMS |
| — | **W41-11** | Q5 alt | K8s cluster JWKS direct validation | auth | M | W36-02 | Optional | TokenReview sufficient for prospect |

> **Tier P sequencing:** **P0** docs in parallel (week 1). **P1** security hardening before Shamir (**W41-05**). **W31-01** must land before **W41-08** → **W41-09** chain. Prospect POC demo can use OpenSSL fallback until **W41-09** merges; **prospect authorization** requires **W41-09** acceptance tests green. **Tier H (W40)** and **LT-14** resume after Tier P exit.

---

## Phase 1 — MVP (Core Foundations)

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W1-01**~~ | ~~Go project scaffold~~ | ci | S | — | Initialize module layout per LLD §3.1 (`go.mod`, `cmd/knxvault/main.go`, directory skeleton). | Done — `go.mod` (Go 1.25), full LLD §3.1 tree, bootstrapped HTTP server (`/health`, `/ready`), config, envelope crypto stub, OpenAPI stub. |
| ~~**W1-02**~~ | ~~Production Makefile (fmt, vet, lint, test, build, sbom, scan)~~ | ci | S | W1-01 | Root `Makefile` providing the standard Go developer/CI workflow referenced in LLD §3.1 and §9.5 (SBOM generation). | Done — `make all` passes; `make` defaults to `help`; static `bin/knxvault`; CycloneDX `sbom.json` + `sbom-binary.json`; Trivy scan clean (`.trivyignore` for unused transitive paths); `GOTOOLCHAIN=go1.25.11`; golangci-lint v2. |
| ~~**W2-01**~~ | ~~Licensing policy & allow-list~~ | docs | S | W1-01 | Document permissive-only dependency policy per LLD §1.5. | Done — `docs/licensing.md`, `config/licenses.allow`. |
| ~~**W2-02**~~ | ~~License CI gate (`go-licenses`)~~ | ci | S | W2-01 | Enforce SPDX allow-list in local/CI builds. | Done — `scripts/check-licenses.sh`, `make licenses`, included in `make all`. |
| ~~**W3-01**~~ | ~~Master key loader~~ | crypto | S | W1-01 | Load 32-byte master key from env or file. | Done — `internal/crypto/masterkey/loader.go` + tests. |
| ~~**W3-02**~~ | ~~Envelope crypto service~~ | crypto | S | W3-01 | DEK generation, master-key-wrapped DEKs, Seal/Open. | Done — `internal/crypto/service.go` + tests. |
| ~~**W3-03**~~ | ~~OpenSSL CLI wrapper~~ | crypto | M | W1-01 | Sandboxed OpenSSL execution per LLD §4.A.1. | Done — `internal/crypto/openssl/wrapper.go` + tests. |
| ~~**W3-04**~~ | ~~Crypto bootstrap wiring~~ | crypto | S | W3-01, W3-02, W3-03 | Wire master key, crypto service, and OpenSSL into app startup. | Done — `internal/app/deps.go`, extended `internal/config/config.go`. |
| ~~**W4-01**~~ | ~~Domain models (CA, Secret, Audit)~~ | storage | S | W1-01 | Pure domain entities with validation. | Done — `internal/domain/pki`, `secrets`, `audit` + unit tests. |
| ~~**W4-02**~~ | ~~Initial persistence design~~ _(superseded)_ | storage | S | W4-01 | Early schema exploration. | **Superseded by W25** Dragonboat state machine. |
| ~~**W4-03**~~ | ~~Repository interfaces~~ | storage | S | W4-01 | CA, Secret, Audit interfaces per LLD §4.D.3. | Done — `internal/repository/interfaces.go`; **retained** for Dragonboat adapters. |
| ~~**W4-04**~~ | ~~Repository implementations~~ _(superseded)_ | storage | M | W4-02, W4-03 | Persistence adapters for cas, secret_versions, audit_logs. | **Replaced by W26** — `internal/repository/dragonboat/`. |
| ~~**W4-05**~~ | ~~Repository unit & integration tests~~ | storage | M | W4-04 | In-memory fakes + integration tests. | Done — `internal/repository/memory/*`; extended by **W28** Raft suite. |
| ~~**W4-06**~~ | ~~Storage bootstrap wiring~~ _(superseded)_ | storage | S | W4-04 | Connect persistence layer, readiness check. | **Replaced by W24** NodeHost bootstrap. |
| ~~**W5-01**~~ | ~~PKI engine (root CA)~~ | crypto | M | W3-03, W4-04 | Create self-signed root CA via OpenSSL, encrypt key material. | Done — `internal/engine/pki/engine.go` `CreateRoot` + tests. |
| ~~**W5-02**~~ | ~~PKI engine (intermediate CA)~~ | crypto | M | W5-01 | Sign intermediate CAs chained to parent. | Done — `CreateIntermediate` with parent key decryption + signing. |
| ~~**W5-03**~~ | ~~PKI engine (leaf issuance)~~ | crypto | M | W5-01 | Issue leaf certificates with SAN support. | Done — `IssueCertificate` with DNS SAN via OpenSSL extfile. |
| ~~**W5-04**~~ | ~~PKI revocation & CRL~~ | crypto | M | W5-01, W4-04 | Revoke serials, generate PEM CRL. | Done — `RevocationRepository`, `Revoke` + `GenerateCRL`. |
| ~~**W5-05**~~ | ~~PKI service layer~~ | crypto | S | W5-01–W5-04 | Orchestrate PKI with audit logging. | Done — `internal/service/pki.go`. |
| ~~**W6-01**~~ | ~~KVv2 engine~~ | crypto | M | W3-02, W4-04 | Versioned encrypted secrets with TTL and CAS. | Done — `internal/engine/secrets/kvv2.go` + tests. |
| ~~**W6-02**~~ | ~~Secrets service layer~~ | crypto | S | W6-01 | Orchestrate KV operations with audit logging. | Done — `internal/service/secrets.go`. |
| ~~**W7-01**~~ | ~~RBAC policy model~~ | auth | S | W1-01 | Policy/role domain model per LLD §4.C.2. | Done — `internal/domain/auth/policy.go` + tests. |
| ~~**W7-02**~~ | ~~Token authentication~~ | auth | M | W7-01 | Opaque client tokens + bootstrap root token. | Done — `internal/auth/token.go` + tests. |
| ~~**W7-03**~~ | ~~Kubernetes JWT login~~ | auth | M | W7-02 | Service account JWT login mapped to roles. | Done — `LoginKubernetes` with HS256 JWT validation. |
| ~~**W7-04**~~ | ~~Audit service (hash chain)~~ | auth | M | W4-04 | Append-only audit with SHA-256 hash chaining. | Done — `internal/audit/service.go` + `LatestHash` on repos. |
| ~~**W7-05**~~ | ~~Auth middleware~~ | auth | S | W7-02, W7-01 | Bearer token auth + RBAC enforcement. | Done — `internal/api/middleware/auth.go`. |
| ~~**W8-01**~~ | ~~API DTOs & handlers~~ | api | M | W5-05, W6-02, W7-05 | REST handlers for auth, PKI, secrets, sys. | Done — `internal/api/handlers/*`, `internal/api/dto/*`. |
| ~~**W8-02**~~ | ~~API middleware (errors, request ID)~~ | api | S | W8-01 | Standardized errors and `X-Request-ID`. | Done — `internal/api/middleware/errors.go`, `requestid.go`. |
| ~~**W8-03**~~ | ~~OpenAPI spec & Swagger UI~~ | api | M | W8-01 | Full `api/openapi.yaml` + `/swagger` UI. | Done — OpenAPI 3.1 spec, `/openapi.yaml`, `/swagger`. |
| ~~**W8-04**~~ | ~~Router wiring~~ | api | S | W8-01–W8-03 | Register all routes with auth/RBAC groups. | Done — `internal/api/router.go`, `internal/app/deps.go`. |

---

## Phase 1 — MVP (remaining)

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W9-01**~~ | ~~Container image (Dockerfile)~~ | k8s | S | W1-02 | Multi-stage Dockerfile producing a minimal non-root image. | Done — `Dockerfile`, `.dockerignore`, `make docker-build`, `-healthcheck` flag. |
| ~~**W9-02**~~ | ~~Raw Kubernetes manifests~~ | k8s | M | W9-01 | Deployment, Service, ConfigMap/Secret templates (no Helm). | Done — `deployments/k8s/*`, `docs/deploy/kubernetes.md`. |
| ~~**W10-01**~~ | ~~Prometheus metrics~~ | docs | M | W8-04 | `/metrics` endpoint with request/latency counters. | Done — `internal/infra/metrics`, `docs/metrics.md`. |
| ~~**W10-02**~~ | ~~Structured logging polish~~ | docs | S | W8-04 | Request ID in logs, consistent zap fields. | Done — `request_id`, `actor`, `route` in request logs + tests. |
| ~~**W11-01**~~ | ~~Integration test suite~~ | ci | M | W9-01, W4-05 | API integration tests. | Done — `test/integration/*`; **extended by W28** for 3-node Raft. |
| ~~**W11-02**~~ | ~~Security scan gates (gosec)~~ | security | S | W1-02 | Add gosec to Makefile / `make all`. | Done — `make gosec`, `.gosec.json`, included in `make all`. |

> **Note:** Helm chart deferred to [Long-term future](#long-term-future) — Phase 1 uses Dockerfile + raw K8s manifests only.

---

## Phase 2 — Enterprise (complete)

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W12-01**~~ | ~~Dynamic DB credentials engine~~ | crypto | M | W6-01, W4-04 | Database credentials engine with lease lifecycle and rotation. | Done — `internal/engine/secrets/database/`, `leases` + `database_roles` tables, `/secrets/database/*` API, lease renew/revoke, background cleanup job. |
| ~~**W12-02**~~ | ~~Lease repository~~ | storage | S | W12-01 | Persist leases and database role configuration. | Done — memory + Dragonboat; **delivered in W25**. |
| ~~**W13-01**~~ | ~~RBAC conditions evaluator~~ | auth | M | W7-01 | Policy conditions (`ip_cidr`, `time_after`/`time_before`, `path_prefix`, `namespace`). | Done — `internal/auth/evaluator.go` + tests, wired into auth middleware. |
| ~~**W13-02**~~ | ~~Persisted policies & roles~~ | auth | M | W13-01 | Policy/role CRUD with DB persistence and runtime reload. | Done — `policies` + `roles` tables, `/sys/policies` + `/sys/roles` API. |
| ~~**W14-01**~~ | ~~Audit export API~~ | auth | M | W7-04 | Export audit logs with hash-chain head and HMAC signature. | Done — `GET /audit/export`, details included in hash payload, `KNXVAULT_AUDIT_SIGNING_KEY`. |
| ~~**W14-02**~~ | ~~Audit chain verification~~ | auth | S | W14-01 | Verify hash chain integrity and signature. | Done — `POST /audit/verify`, `internal/audit/service.go` Export/Verify. |
| ~~**W15-01**~~ | ~~Kubernetes Lease leader election~~ _(interim)_ | k8s | M | W9-02 | HA mode with coordination.k8s.io Lease (lightweight HTTP client). | Done (interim) — **superseded by W26** Raft leader for storage + jobs. |
| ~~**W15-02**~~ | ~~Background jobs (lease cleanup, CRL refresh)~~ _(interim)_ | k8s | M | W15-01, W12-01, W5-04 | Leader-only periodic jobs for lease cleanup and CRL refresh. | Done (interim) — **retarget to W26** Raft leader gating. |

| ~~**W16-01**~~ | ~~Certificate renewal automation~~ | crypto | M | W5-03, W15-02 | TTL-based renewal API and background job with grace window. | Done — `issued_certificates` table, `POST /pki/renew`, `auto_renew` on issue, leader job. |
| ~~**W17-01**~~ | ~~OCSP responder (basic)~~ | crypto | M | W5-04 | DER OCSP endpoint with good/revoked status. | Done — `POST /pki/ocsp/:id`, `internal/engine/pki/ocsp.go` + tests. |
| ~~**W18-01**~~ | ~~Secrets injection render API~~ | k8s | M | W6-01 | Sidecar/init-container render endpoint. | Done — `POST /inject/render`, `internal/inject/`, sidecar example manifest. |
| ~~**W18-02**~~ | ~~CSI provider scaffolding~~ | k8s | S | W18-01 | CSI provider interface and K8s DaemonSet template. | Done — `internal/inject/csi/`, `deployments/csi/`, `docs/deploy/secrets-injection.md`. |
| ~~**W19-01**~~ | ~~Rate limiting~~ | security | M | W8-04 | Per-token/IP token-bucket rate limiting on secured routes. | Done — `internal/api/middleware/ratelimit.go`, `knxvault_rate_limited_total` metric. |
| ~~**W19-02**~~ | ~~Request signing~~ | security | M | W7-05 | Optional HMAC request signatures with timestamp skew check. | Done — `internal/api/middleware/signing.go`, `KNXVAULT_REQUEST_SIGNING_*` config. |

| ~~**W20-01**~~ | ~~Administration CLI~~ | docs | M | W8-04 | Cobra CLI + `pkg/client` SDK for Day-2 operations. | Done — `cmd/knxvault-cli`, `make build-cli`, `docs/cli/reference.md`. |
| ~~**W21-01**~~ | ~~Backup & restore~~ _(interim)_ | storage | M | W4-04, W3-02 | Encrypted snapshot export/import API and runbooks. | Done (interim) — `internal/backup/`; **extended by W27** for Dragonboat snapshots. |
| ~~**W22-01**~~ | ~~Tracing & Grafana dashboards~~ | docs | M | W10-01 | OpenTelemetry HTTP tracing and overview dashboard JSON. | Done — `internal/infra/tracing/`, `deployments/grafana/knxvault-overview.json`. |

---

## Phase 3 — Dragonboat storage backend (complete)

Embedded [Dragonboat](https://github.com/lni/dragonboat) Raft cluster for production storage and HA. Default log store: Pebble (Dragonboat default). Repository interfaces unchanged; implementations live under `internal/repository/dragonboat/` and `internal/raft/`.

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W23-01**~~ | ~~Dragonboat dependency & license gate~~ | ci | S | W2-02 | Add `github.com/lni/dragonboat/v3` (or v4 when stable), SPDX check in `config/licenses.allow`, `go mod tidy` clean. | Done — `github.com/lni/dragonboat/v3@v3.3.8`; `make licenses` passes. |
| ~~**W23-02**~~ | ~~Dragonboat storage design doc~~ | docs | M | W23-01 | Update LLD §4.D / §8.3: Raft group layout, command catalog, snapshot format, Pebble data dirs, single-node vs 3-node topology. | Done — [`docs/storage/dragonboat.md`](storage/dragonboat.md). |
| ~~**W24-01**~~ | ~~NodeHost bootstrap & config~~ | storage | M | W23-01 | `internal/raft/nodehost.go`: `NodeHost` lifecycle, `KNXVAULT_RAFT_*` config (node ID, peers, data dir, election RTT). | Server starts with Raft enabled; `/ready` reports `raft_ready` + `leader`. |
| ~~**W24-02**~~ | ~~Vault state machine skeleton~~ | storage | M | W24-01 | `internal/raft/statemachine.go` implementing `statemachine.IStateMachine`: `Update`, `Lookup`, `SaveSnapshot`, `RecoverFromSnapshot`. | Unit tests apply noop commands; snapshot round-trip passes. |
| ~~**W25-01**~~ | ~~State machine — core entities~~ | storage | L | W24-02, W4-03 | Commands for CA, secret versions, audit append (hash chain), revocations. Dragonboat repo adapters implement `repository.*` interfaces. | PKI + KV + audit integration tests pass on single-node Raft. |
| ~~**W25-02**~~ | ~~State machine — Phase 2 entities~~ | storage | M | W25-01 | Commands for leases, policies, roles, database roles, issued certificates. | Dynamic secrets + RBAC persistence tests pass on Raft. |
| ~~**W26-01**~~ | ~~Wire Dragonboat into `app/deps`~~ | storage | M | W25-02 | Use Raft repos when `KNXVAULT_RAFT_ENABLED=true`; keep memory mode for tests. | `make test` passes; production runs on Dragonboat only. |
| ~~**W26-02**~~ | ~~Raft leader for background jobs~~ | k8s | M | W26-01, W15-02 | Gate `JobRunner` on Dragonboat leader ID instead of K8s Lease when Raft enabled; expose `knxvault_raft_leader` metric. | Only Raft leader runs lease cleanup / CRL refresh / cert renewal. |
| ~~**W27-01**~~ | ~~Dragonboat snapshot backup~~ | storage | M | W26-01, W21-01 | Integrate Dragonboat `SaveSnapshot` / on-disk snapshots with `POST /sys/backup`; restore via `RecoverFromSnapshot` + state machine import. | Backup/restore round-trip on 3-node cluster. |
| ~~**W27-02**~~ | ~~Backup import to Raft~~ _(superseded)_ | storage | M | W26-01 | Seed Raft cluster from encrypted backup archive. | Superseded by `snapshot.import` via `POST /sys/restore`. |
| ~~**W28-01**~~ | ~~3-node Raft integration tests~~ | ci | L | W26-01 | `test/integration/raft_*`: 3 processes or docker-compose with distinct `KNXVAULT_RAFT_NODE_ID` / peer lists; verify linearizable writes and leader failover. | `make test-integration` includes Raft suite. |
| ~~**W28-02**~~ | ~~Kubernetes StatefulSet manifests~~ | k8s | M | W24-01 | Replace Deployment+Lease with StatefulSet, headless Service, PVC per replica, `KNXVAULT_RAFT_INITIAL_MEMBERS` ConfigMap. | `docs/deploy/kubernetes.md` updated; 3-replica Raft deploy verified. |
| ~~**W29-01**~~ | ~~Finalize Dragonboat as sole backend~~ | storage | S | W28-01 | Dragonboat-only production path; in-memory for dev when Raft disabled. | README lists Dragonboat as required backend. |
| ~~**W29-02**~~ | ~~Observability for Raft~~ | docs | S | W26-02, W22-01 | Prometheus: Raft term, leader, commit index, propose latency; Grafana panel additions. | `docs/metrics.md` + dashboard JSON updated. |

### Phase 3 — configuration (target)

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_RAFT_ENABLED` | `true` | Use Dragonboat backend (false = in-memory dev only) |
| `KNXVAULT_RAFT_NODE_ID` | `1` | Raft node ID (unique per replica) |
| `KNXVAULT_RAFT_DATA_DIR` | `/var/lib/knxvault/raft` | Pebble WAL + snapshot directory |
| `KNXVAULT_RAFT_INITIAL_MEMBERS` | _(required in HA)_ | Comma-separated `id=host:port` peer list |
| `KNXVAULT_RAFT_ELECTION_RTT` | `10` | Election RTT (Dragonboat tuning) |
| `KNXVAULT_RAFT_HEARTBEAT_RTT` | `1` | Heartbeat RTT |

---

## Phase 4 — Production hardening (gap closure)

Items below come from a **2026-06 codebase gap analysis**, a **secrets manager checklist** comparison, and an **`docs/lld.md` alignment review** (2026-06). Implement **Tier 0 → Tier A blockers → Tier G (CSI) → Tier F → remaining Tiers A–E** before Phase 5 ecosystem work. **Secrets Store CSI Driver is the primary Kubernetes-native consumption path** (sidecar/init remain fallbacks). **Helm, Terraform, and AWS/cloud IAM engines are long-term only** (LT-*). Descriptions include **file hints** (`path:symbol`) to start quickly.

### Tier 0 — Secrets manager checklist (Priority 0)

**Take these up before Tier A.** Maps to common secrets-manager evaluation criteria (encryption in transit, automated rotation, NHI/AI agents, dynamic credentials, exposure detection, enterprise integrations). Several items depend on **W36-01** (fail-closed auth) and **W36-04** (master key required) — implement those in parallel if blocked.

| ID | Checklist criterion | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|---------------------|-------|------|--------|------------|-------------|---------------------|
| ~~**W37-01**~~ | Encryption in transit | ~~Server TLS and optional mTLS~~ | security | M | W36-04 | Done — `internal/crypto/tlsconfig/`, `KNXVAULT_TLS_*`, mTLS on KV writes, `internal/api/middleware/mtls.go`. | HTTPS + mTLS gate; tests in `tlsconfig_test.go`. |
| ~~**W37-02**~~ | Short-lived credentials | ~~OIDC/JWT auth method~~ | auth | L | W36-01, W36-13 | Done — `POST /auth/oidc/:role`, `internal/auth/oidc.go`, role `OIDC` config. | Wrong `aud`/`iss` rejected; `oidc_test.go`. |
| ~~**W37-03**~~ | NHI — machine identities | ~~Machine identity registry (NHI)~~ | auth | L | W36-02, W36-03, W36-13 | Done — `MachineIdentity` domain, Raft ops, `GET /sys/machine-identities`, login upsert + revoke. | NHI lifecycle + audit `nhi.login`. |
| **W37-04** | NHI / AI agents | AI agent scoped auth & delegation | auth | M | W37-02, W37-03 | **Gap:** No agent-specific vaults, delegation chains, or tool-scoped policies for autonomous workloads. **Hint:** Extend `MachineIdentity` with `parent_identity_id` and `allowed_actions[]` (e.g. `secrets/kv:read:agent/*` only). Add `POST /auth/agent/delegate` — parent token mints child token with **narrower** policies and **shorter TTL** (cap 15m). Policy condition `agent_id` in `internal/auth/evaluator.go`. Optional KV path prefix `agent/{identity_id}/*` enforced in middleware. | Parent CI token delegates 15m agent token; agent cannot access paths outside prefix. Delegation audited with parent→child link. |
| ~~**W37-05**~~ | Automated rotation | ~~Scheduled KV secret rotation~~ | crypto | M | W36-05, W36-17 | Done — `RotationPolicy` Raft entity, `runKVRotation` job, `PUT /sys/kv-rotation`, `random_password` generator. | Leader-only rotation + `secret.rotate` audit. |
| ~~**W37-06**~~ | ~~Automated rotation~~ | ~~End-to-end rotation orchestration~~ | crypto | L | W37-05, W36-18 | Done — `POST /sys/rotation/run`, `RenewExpiring` DB leases, KV `RunDue`, rotation webhook. | DB lease auto-renewed before TTL; KV rotated per W37-05; webhook receives event; audit trail links old→new version/lease. |
| ~~**W37-07**~~ | Exposure detection | ~~Secret exposure webhook & auto-remediation hooks~~ | security | L | W37-05, W36-17 | Done — `POST /sys/exposure/report` HMAC-signed, auto-revoke/rotate, `docs/integration/exposure-detection.md`. | Unsigned report rejected; webhook + remediation. |
| **W37-08** | Integrations | Multi-language SDK via OpenAPI codegen | docs | M | W40-03 | **Superseded by Tier H** [**W40-03–W40-07**](#tier-h--kubernetes-ecosystem-eso-cert-manager-sdks). Go reference: `pkg/client`. | — |
| ~~**W37-09**~~ | Checklist / docs | ~~Secrets manager capability matrix~~ | docs | S | W37-01–W37-07 | Done — `docs/product/secrets-manager-checklist.md` + Tier I enterprise table; PoC guide `docs/product/poc-evaluation-guide.md`. | Matrix covers checklist + W41-* enterprise items; linked from `docs/README.md`. |

> **Tier 0 sequencing:** **W37-01** (TLS) + **W37-02** (OIDC) unblock most NHI/dynamic-cred work. **W37-07** (exposure) can start after rotation hooks (**W37-05**). **W37-08** (SDKs) after Tier A auth blockers (**W36-01–W36-04**). **At rest encryption** is already implemented (envelope + Raft); maintain via **W36-04**. Near-term K8s deploy: raw manifests (`deployments/k8s/`). **Helm** (**LT-03**), **Terraform** (**LT-01**), **AWS IAM** (**LT-02**) → [long-term future](#long-term-future).

### Tier G — Kubernetes-native consumption (CSI first) — **shipped**

**Product direction:** KNXVault is a Kubernetes-native secrets platform — [**Secrets Store CSI Driver**](https://secrets-store-csi-driver.sigs.k8s.io/) integration is **first-class**, not a Phase 2 afterthought. **Status (2026-06):** W39-01–W39-08 implemented (`knxvault-csi`, manifests, docs, tests). Workloads mount secrets as volumes via `SecretProviderClass`; sidecar/init patterns (**W18**) are **fallbacks** for clusters without CSI or legacy apps. **Helm packaging of the CSI provider DaemonSet stays long-term (LT-03)**; near-term manifests live in `deployments/csi/`.

| ID | LLD § | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|-------|------|--------|------------|-------------|---------------------|
| ~~**W39-01**~~ | §6.4 | ~~CSI provider gRPC server (`knxvault-csi`)~~ | k8s | L | W18-02, W36-02 | Done — `cmd/knxvault-csi`, `internal/inject/csi/server.go`, `make build-csi`. | Provider registers with driver; `Mount` returns file objects for configured KV paths. |
| ~~**W39-02**~~ | §6.4, §4.C.1 | ~~Pod identity auth on CSI mount (no static tokens)~~ | auth | M | W39-01, W36-02, W36-03 | Done — SA JWT from mount attributes + TokenReview per mount. | Pod with bound SA mounts secret; wrong SA → mount fails; no long-lived token in provider pod. |
| ~~**W39-03**~~ | §6.4 | ~~`SecretProviderClass` schema and reference manifests~~ | k8s | S | W39-01 | Done — `deployments/csi/secretproviderclass-example.yaml`, `pod-example.yaml`, `docs/deploy/secrets-injection.md`. | `kubectl apply` + example pod reads mounted file in kind cluster. |
| ~~**W39-04**~~ | §6.4 | ~~CSI provider DaemonSet, RBAC, and install runbook~~ | k8s | M | W39-01, W38-05 | Done — `deployments/csi/k8s-provider.yaml`, `rbac.yaml`, `docs/deploy/csi-install.md`. | Fresh kind cluster: driver + provider + example pod end-to-end per runbook. |
| ~~**W39-05**~~ | §6.4, §7.2 | ~~CSI secret rotation and driver reload~~ | k8s | M | W39-01, W37-05 | Done — `knxvault_csi_mount_rotations_total`, SPC rotation docs, Mount version detection. | KV version bump detected on remount. |
| ~~**W39-06**~~ | §6.4 | ~~Optional sync to native Kubernetes `Secret`~~ | k8s | S | W39-03 | Done — `secretObjects` in `secretproviderclass-example.yaml`; etcd trade-off documented in `docs/deploy/secrets-injection.md`. | `secretObjects` creates synced Secret; envFrom works; doc warns about duplicate plaintext in etcd. |
| **W39-07** | §6.4, §9.5 | CSI end-to-end integration test (kind) | ci | M | W39-04 | **Gap:** No automated CSI path validation. **Hint:** `test/integration/csi_test.go` or `scripts/test-csi-kind.sh`: kind + install driver + deploy provider + example SPC; assert file content matches KV put. Gate optional in CI (requires Docker). | Script passes locally; documented in `docs/engineering/development.md`. |
| ~~**W39-08**~~ | §6.4, §12 | ~~Product docs — CSI as primary K8s integration~~ | docs | S | W39-03 | Done — CSI-first in `docs/deploy/secrets-injection.md`, `docs/integration/kubernetes-native.md`, README. | New operator onboarding path leads with CSI; sidecar labeled fallback. |

> **Tier G sequencing:** **W39-01** after **W36-02** (TokenReview). **W37-01** (TLS) recommended before production in-cluster `vaultAddr`. **W39-03–W39-04** parallel once **W39-01** skeleton mounts. **W39-05** after **W37-05**. **W38-07** (mutating webhook) **defers** until Tier G baseline ships — webhook is convenience, not primary.

### Tier H — Kubernetes ecosystem (ESO, cert-manager, SDKs)

**Product direction:** Full Kubernetes-native surface documented in [`docs/integration/kubernetes-native.md`](integration/kubernetes-native.md). CSI + K8s auth + webhook are shipped; this tier completes **External Secrets Operator**, **cert-manager Issuer**, and **multi-language SDKs**.

| ID | Integration | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------------|-------|------|--------|------------|-------------|---------------------|
| ~~**W40-01**~~ | External Secrets Operator | ~~Native ESO `knxvault` provider~~ | k8s | L | W39-02, W36-03 | Done — `cmd/knxvault-eso`, `deployments/external-secrets/clustersecretstore-knxvault.yaml`. | `ExternalSecret` creates/updates K8s `Secret`; refresh picks up new KV version. |
| ~~**W40-02**~~ | cert-manager | ~~cert-manager Issuer for KNXVault PKI~~ | crypto | L | W38-03, W36-02 | Done — Vault shim `/v1/pki/sign/:role`, `/v1/auth/kubernetes`; `deployments/cert-manager/`. | `Certificate` resource becomes Ready; TLS Secret contains issued leaf + key. |
| ~~**W40-03**~~ | SDKs | ~~OpenAPI client generation pipeline~~ | docs | S | W8-03 | Done — `scripts/generate-clients.sh`, `make generate-clients`, `make test-clients`. | `make generate-clients` produces Python/TS/Java/Rust trees. |
| ~~**W40-04**~~ | SDKs | ~~Python client (`clients/python`)~~ | docs | M | W40-03 | Done — `clients/python/knxvault/`, `tests/clients/test_python.py`. | `pip install` + 3-line example works against dev server. |
| ~~**W40-05**~~ | SDKs | ~~Node.js / TypeScript client (`clients/typescript`)~~ | docs | M | W40-03 | Done — `clients/typescript/`, `@knxvault/client`. | `npm install` + health/kv smoke passes. |
| ~~**W40-06**~~ | SDKs | ~~Java client (`clients/java`)~~ | docs | M | W40-03 | Done — `clients/java/`, JUnit smoke test. | Maven dependency resolves; integration test passes. |
| ~~**W40-07**~~ | SDKs | ~~Rust client (`clients/rust`)~~ | docs | M | W40-03 | Done — `clients/rust/`, `cargo test` smoke. | `cargo add` + example compiles and calls health. |
| **W40-08** | Docs | Kubernetes-native integration matrix | docs | S | W40-01 | **Gap:** Operators need single status page. **Hint:** Keep [`docs/integration/kubernetes-native.md`](integration/kubernetes-native.md) current; link from README, `docs/README.md`, W37-09 checklist. Reconcile ✅/planned per release. | All six integrations listed with code path or backlog ID. |

> **Tier H sequencing:** **W40-03** first (codegen pipeline). **W40-04–07** parallel after W40-03. **W40-01** after Tier G auth (**W39-02**). **W40-02** after PKI roles (**W38-03**) or Vault shim without roles (interim).

### Tier I — Enterprise security & compliance (v1.0–v1.2)

Items from the **2026-07 enterprise architecture security review**. **Prospect POC immediate items** → [**Tier P**](#tier-p--prospect-poc-immediate-july-2026-enterprise-memorandum) (supersedes timing below). Remaining Tier I after Tier P exit: **W41-14**, **W41-11**, **W31-03**. **Cloud KMS (AWS/GCP/Azure)** → **LT-14**, **LT-15**. **Seal/unseal model:** [ADR-0006](adr/0006-seal-unseal-strategies.md). Customer-facing scope: [`docs/product/poc-evaluation-guide.md`](product/poc-evaluation-guide.md).

| ID | Tier P priority | Notes |
|----|-----------------|-------|
| W41-01, W41-02, W41-05, W41-06, W41-07, W41-08, W41-09, W41-10, W41-12, W41-13, W41-15, W31-01, W38-15 | **P0–P3** | See Tier P sequence |
| W41-14 | Post-prospect | Requires **LT-14** |
| W41-11 | Optional | TokenReview enough for prospect |

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| **W41-01** | Memory lock (`mlock`) for master and unseal keys | security | M | W36-04, W36-24 | **Gap:** Master key and unseal key buffers live in ordinary heap memory; crash dumps may retain plaintext. No `mlock`/`Mlockall` today (`internal/crypto/masterkey/loader.go`, `internal/app/seal.go`). **Hint:** Add `internal/crypto/memlock/memlock.go` wrapping `syscall.Mlock` (Linux) with build tags for unsupported platforms (no-op stub). Lock `[]byte` returned by master key loader and `SealState.unsealKey` immediately after load; unlock only on graceful shutdown via `defer` in `internal/app/deps.go`. Document `RLIMIT_MEMLOCK` requirement in `docs/installation/configuration.md` and K8s manifest `securityContext` (may need `capabilities.add: [IPC_LOCK]` — evaluate whether non-root UID 65532 can mlock without cap). Add integration test verifying locked pages are not swapped (best-effort on CI). Cross-reference [ADR-0003](adr/0003-envelope-encryption.md) follow-up. | Master key buffer mlocked at startup; unit test on Linux; operator doc lists memlock prerequisite; no regression in `make test`. |
| **W41-02** | Universal sensitive-buffer lifecycle audit | security | M | W38-10, W41-01 | **Gap:** `memzero.Bytes()` is used on decrypted CA keys in PKI (`internal/engine/pki/engine.go`) but not uniformly on DEK plaintext, JWT parsing buffers, unseal request bodies, or backup restore payloads. **Hint:** Introduce `internal/crypto/sensitive` package: `type Buffer struct` wrapping `[]byte` with `Close()` → memzero + optional munlock; migrate `internal/crypto/service.go` `Open()` return type to `*sensitive.Buffer`. Audit grep for `[]byte` key/password paths in `internal/auth/`, `internal/backup/`, `internal/api/handlers/sys.go` (unseal). Add `make audit-sensitive` script (gosec + custom grep rules). Document residual risk (Go GC string interning) in `docs/architecture/security-model.md`. | All identified secret byte paths use `sensitive.Buffer` or explicit `memzero`; audit script passes; security-model updated. |
| **W41-05** | Shamir threshold unseal (k-of-n shares on **unseal key**) | security | L | W36-24, W41-01 | **Gap:** Single `KNXVAULT_UNSEAL_KEY` — no separation of duties; one operator or one Secret compromise unseals vault. **Decision ([ADR-0006](adr/0006-seal-unseal-strategies.md)):** Shamir applies to the **operational unseal key** only — **not** the master key. Master key custody stays KMS/HSM/sealed Secret; loss recovery uses backup + `POST /sys/rotate-master-key` (W36-17). **Hint:** Split `KNXVAULT_UNSEAL_KEY` via `github.com/hashicorp/vault/shamir` or in-tree GF(256) in `internal/crypto/shamir/`. At init, derive unseal key from shares in memory once per ceremony; shares never persisted in Raft. API: `POST /sys/unseal` accepts `{"key":"<base64 share>","share_id":1}` — track `unseal_progress` server-side (reset on seal). CLI: `knxvault-cli sys init-shamir --shares 5 --threshold 3` outputs shares once (stdout only). Config: `KNXVAULT_UNSEAL_SCHEME=shamir`, `KNXVAULT_UNSEAL_THRESHOLD`. Single-key mode remains default. Document in `docs/operations/shamir-unseal.md` with explicit “not for master key” banner. | 3-of-5 shares reconstruct unseal key and unseal; 2 shares insufficient; master key unchanged; Shamir shares ≠ master key; rate limit applies. |
| **W41-14** | Dual-mode seal (KMS auto-unseal + Shamir break-glass) | security | M | W41-05, LT-14 | **Gap:** **LT-14** and **W41-05** are specified independently; production Vault-style posture needs both. **Decision ([ADR-0006](adr/0006-seal-unseal-strategies.md)):** KMS handles routine restarts; Shamir is break-glass when KMS unavailable or after manual `POST /sys/seal`. **Hint:** Config matrix in `internal/config/seal.go`: `auto_unseal { provider, kms_* }` mutually exclusive with active Shamir only when `break_glass_shamir=true`. Startup: try KMS unseal blob first → on failure stay sealed and accept Shamir shares via `POST /sys/unseal`. Master key load path unchanged (KMS-wrapped master ciphertext separate from unseal blob). Metrics: `knxvault_auto_unseal_success_total`, `knxvault_shamir_unseal_total`. Document precedence and failure modes in `docs/operations/dual-mode-unseal.md`. | With KMS up: restart auto-unseals without shares; with KMS down: 3-of-5 Shamir unseals; manual seal requires Shamir or KMS per config. |
| **W41-06** | Hierarchical client tokens & cascade revocation | auth | L | W36-13, W38-02 | **Gap:** `RevokeToken` (`internal/auth/token.go`) revokes one token; no parent-child tree; revoking an admin token does not invalidate delegated workload tokens. **Hint:** Extend `domain/auth` token entity with `ParentID *uuid.UUID`, `Path string` (hierarchy label). On `POST /auth/token/create`, set `ParentID` to caller token ID. Raft commands `token.save` carry parent link. New `POST /auth/token/revoke-tree` (sudo) or automatic cascade when parent revoked: BFS revoke all descendants in `TokenStore`. Add `orphan` policy option on create (token survives parent revoke — default false for compliance). Metric `knxvault_tokens_revoked_cascade_total`. Update OpenAPI + `docs/architecture/security-model.md`. | Parent revoke invalidates child tokens within one Raft round-trip; integration test 3-level tree; audit logs cascade count. |
| **W41-07** | OIDC group and claim → policy mapping | auth | M | W37-02, W36-03 | **Gap:** OIDC login (`internal/auth/oidc.go`) validates `iss`/`aud`/`sub` via JWKS but roles only bind static policy name lists — no mapping from AD/Azure `groups[]` or custom claims to policies. **Hint:** Extend `domain/auth.OIDCConfig` with `ClaimMappings []ClaimMapping` (`claim: groups`, `match: regex or exact`, `policies: []string`). Evaluator in `internal/auth/oidc.go` after JWT validate: extract claim (support string or `[]string`), match rules, union policies with role defaults. Optional `bound_claims map[string]string` for required claim values (like SA binding). API: extend `PUT /sys/roles/:name` DTO. Document Entra ID / Okta examples in `docs/integration/oidc-claim-mapping.md`. | User in `groups: ["vault-admins"]` receives admin policy; user without matching group → `403`; tests with mock JWKS + claims. |
| **W41-08** | Go-native `crypto/x509` read and verify fast path | crypto | M | W31-01 | **Gap:** All X.509 parse/verify goes through OpenSSL subprocess or ad-hoc `x509.ParseCertificate` in PKI engine; no unified native backend. **Hint:** New `internal/crypto/x509native/` package implementing `CryptoBackend` interface (mirror of **W31-01**): `ParseCertificate`, `VerifyChain`, `ParseCRL`, `BuildCertPool`. Route read-only handlers (`GET /pki/ca/*`, CRL download, OCSP verify path) through native backend when `KNXVAULT_PKI_BACKEND=native` (per-op fallback to OpenSSL on unsupported extensions). Reuse existing `parseCertificate` in `internal/engine/pki/engine.go`. Benchmark vs OpenSSL in **LT-12**. | Native path parses issued certs and validates chains; integration test matches OpenSSL output for RSA SHA-256 certs. |
| **W41-09** | Go-native `crypto/x509` full PKI issuance engine | crypto | XL | W41-08, W31-01 | **Gap:** PKI mutating operations (root/intermediate/leaf, CRL sign, OCSP sign) require OpenSSL subprocess (`internal/engine/pki/engine.go` → `SafeExec`). Enterprise review requests elimination of fork-per-operation pattern. **Hint:** Implement `IssueCertificate`, `CreateRoot`, `CreateIntermediate`, `GenerateCRL`, `SignOCSP` in `internal/crypto/x509native/issuer.go` using `x509.CreateCertificate`, `x509.RevocationList`, `golang.org/x/crypto/ocsp`. Port SAN handling from extfile logic to `pkix.Extension` building. Property-based tests comparing PEM output to OpenSSL golden files in `testdata/pki/`. Feature flag `KNXVAULT_PKI_BACKEND=native` (default `openssl` until parity proven). Keep OpenSSL wrapper as fallback for exotic key types (ECDSA P-384, Ed25519) initially. | Full PKI integration test suite passes with `native` backend; no `exec` of openssl in PKI path when native enabled; issuance bench within 2× of OpenSSL. |
| **W41-10** | OpenSSL subprocess deprecation and optional mode | crypto | M | W41-09, LT-12 | **Gap:** Even after native backend ships, Dockerfile and docs still require OpenSSL in image. **Hint:** When `KNXVAULT_PKI_BACKEND=native` and no HSM engine configured, skip OpenSSL binary check at startup (`internal/app/deps.go`). Provide `Dockerfile.distroless` (no OpenSSL) gated on **W41-09** parity. Deprecation notice in [ADR-0002](adr/0002-openssl-cli-crypto-backend.md) — status → "Superseded by native path". Migration guide in `docs/operations/pki-openssl-migration.md`. | Distroless image issues RSA leaf cert via native backend; `knxvault-cli doctor` warns if OpenSSL missing but native enabled. |
| **W41-11** | Kubernetes cluster JWKS direct SA token validation | auth | M | W36-02 | **Gap:** Production path uses TokenReview API (`internal/infra/k8s/tokenreview.go`) — correct but requires live API server on every login. Some regulated environments want offline asymmetric validation against cluster JWKS (`https://<apiserver>/openid/v1/jwks` or `/.well-known/openid-configuration`). **Hint:** Add `KNXVAULT_K8S_AUTH_MODE=tokenreview` (default) \| `jwks`. JWKS mode: fetch and cache cluster JWKS (reuse `internal/auth/oidc.go` cache pattern), validate SA JWT signature + `iss` + `kubernetes.io/serviceaccount/*` claims locally. Config: `KNXVAULT_K8S_JWKS_URL`, `KNXVAULT_K8S_ISSUER`. Document trade-offs (TokenReview = authoritative revocation; JWKS = offline but no real-time revoke). Forbidden when `k8s_auth_insecure` set. | JWKS mode authenticates valid SA token without TokenReview call; expired token rejected; docs compare modes. |
| **W41-12** | Air-gap OpenSSL CVE patching and image rebuild runbook | docs | S | W9-01, W1-02 | **Gap:** Enterprise air-gap customers need documented procedure for patching OpenSSL 3.x in immutable containers without runtime `apt-get`. **Hint:** Add `docs/operations/runbooks/air-gap-image-patching.md`: (1) monitor Debian security advisories for bookworm OpenSSL; (2) rebuild image `make docker-build` with updated base digest; (3) `make sbom` + `make scan` (Trivy); (4) sign and push to air-gap registry; (5) rolling StatefulSet update with `POST /sys/backup` pre-hook; (6) verify `knxvault-cli doctor` + `openssl version` via exec. Include CVE response SLA template and SBOM diff checklist. Link from [`poc-evaluation-guide.md`](product/poc-evaluation-guide.md). | Runbook steps reproducible in kind; SBOM documents OpenSSL version; linked from docs index. |
| **W41-13** | Seccomp profile for OpenSSL child processes | security | M | W38-21, W3-03 | **Gap:** OpenSSL subprocess inherits container seccomp (`RuntimeDefault`) but no KNXVault-specific syscall allowlist; complements **LT-08** Falco detection with prevention. **Tier P:** **P1** compensating control until **W41-09**. **Hint:** Generate seccomp profile via `docker run --rm seccomp/knxvault-openssl` or hand-write JSON allowing: `read`, `write`, `mmap`, `exit`, `exit_group`, `futex`, `clock_gettime`, `getrandom`, `rt_sigreturn` — deny `execve`, `socket`, `connect`, `chmod` outside tmp. Apply via `securityContext.seccompProfile.localhostProfile` on StatefulSet when `KNXVAULT_OPENSSL_SECCOMP=true`. Test: PKI issuance succeeds with profile; Falco silent. Extend **LT-08** rules to alert on profile bypass. | PKI issue works with custom seccomp; `execve` from OpenSSL child blocked; documented in `deployments/k8s/seccomp-openssl.json`. |
| **W41-15** | Enterprise memorandum traceability matrix | docs | S | W38-19 | **Gap:** Prospect security review (July 2026) needs single living doc mapping memorandum §/Q → implementation status → Tier P priority → compensating control or waiver. **Tier P:** **P0** week 1. **Hint:** `docs/product/enterprise-memorandum-matrix.md` — rows for §2.A–E, Q1–Q6, §5 compensating controls; link ADR-0002/0003/0006, code paths, Tier P IDs. Update on each Tier P ship. Export PDF appendix for prospect data room. Cross-link [`poc-evaluation-guide.md`](product/poc-evaluation-guide.md). | Matrix complete; no “shipped” without code cite; prospect waiver section for LT-14/13. |

> **Tier I sequencing:** **W41-01** + **W41-02** before v1.0 GA (parallel with remaining W36). **W41-05** (Shamir on unseal key) before **W41-14** (dual-mode). **W41-14** depends on **LT-14** for KMS leg — design doc + config stubs can land in v1.1 before cloud SDKs. **W41-06** + **W41-07** are v1.1 auth priorities. **W41-08** → **W41-09** → **W41-10** is the native PKI migration chain (after **W31-01**). **W41-12** can ship immediately (docs-only). **W41-11** optional for air-gapped K8s API constraints. Master key: sealed Secrets near-term; cloud KMS **LT-14**, **LT-15**; HSM wrap **W31-03**. See [ADR-0006](adr/0006-seal-unseal-strategies.md).

### Tier F — LLD alignment (gap closure)

Gaps between **`docs/lld.md`** and the codebase not fully covered by Tier 0 or W36. LLD section references included. **No Helm / Terraform / AWS items here** — those are LT-*.

| ID | LLD § | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|-------|------|--------|------------|-------------|---------------------|
| ~~**W38-01**~~ | §4.B.1, §11.3 | ~~KVv2 list, metadata, and version destroy APIs~~ | api | M | W36-05 | Done — list/metadata/versions/destroy handlers + engine methods. | List returns paths under prefix; destroy v2 keeps v1 readable; retention trims oldest versions on put. |
| ~~**W38-02**~~ | §4.C.1, §11.3 | ~~Token create, renew, and revoke API~~ | auth | M | W36-13 | Done — `POST /auth/token/create`, `/renew`, `DELETE /token/self`. | Admin creates scoped 1h token; renew extends TTL; revoke invalidates immediately. |
| ~~**W38-03**~~ | §1.2, §4.A.3 | ~~PKI issuance roles (incl. code-signing)~~ | crypto | M | W5-03 | Done (minimal) — `domain/pki/role.go`, memory+Raft repos, SAN/TTL validation. | Role rejects bad SAN; code-signing KU deferred. |
| ~~**W38-04**~~ | §1.2 | ~~PKI CA import and export API~~ | crypto | M | W5-01 | Done — `POST /pki/ca/import`, `GET /pki/ca/:id/export`. | Import intermediate from PEM; export returns chain only; audit logged. |
| ~~**W38-05**~~ | §6.5, §7.1 | ~~K8s NetworkPolicy and PDB manifests~~ | k8s | S | W28-02 | Done — `deployments/k8s/networkpolicy.yaml`, `pdb.yaml`. | `kubectl apply` succeeds; policy blocks random pod → 63001; drain respects PDB. |
| ~~**W38-06**~~ | §6.4 | ~~Secrets Store CSI provider binary~~ | k8s | L | W18-02 | **Superseded by Tier G** [**W39-01–W39-08**](#tier-g--kubernetes-native-consumption-csi-first) — CSI is first-class K8s integration. | — |
| ~~**W38-07**~~ | §6.4 | ~~Mutating webhook secrets injection _(optional)_~~ | k8s | L | W39-08, W18-01 | Done — `cmd/knxvault-webhook`, `internal/webhook/mutate.go`, `deployments/k8s/webhook/`. | Annotated pod gets CSI volume without hand-written SPC YAML. |
| ~~**W38-08**~~ | §7.3 | ~~Audit log SIEM streaming~~ | docs | M | W14-01 | Done — `KNXVAULT_AUDIT_FORWARD_URL`, `docs/observability/audit-forwarding.md`. | Each audit record appears in configured sink within 5s; export API unchanged. |
| ~~**W38-09**~~ | §7.3 | ~~Per-entry audit digital signatures~~ | security | M | W14-01 | Done — `Signature` on append + verify in `POST /audit/verify`. | Export includes per-entry signatures; tampered entry fails verify. |
| ~~**W38-10**~~ | §4.A.4 | ~~Secure zeroing of decrypted key material~~ | security | S | W3-03 | Done — `internal/crypto/memzero/memzero.go`. | Unit test passes; PKI paths use memzero. |
| ~~**W38-11**~~ | §10.1 | ~~OpenSSL SafeExec fuzz testing~~ | security | M | W3-03 | Done — `FuzzSafeExec` in `wrapper_test.go`. | Fuzz runs without panic; forbidden args return error. |
| ~~**W38-12**~~ | §11.3 | ~~Admin bootstrap init and rekey API~~ | api | M | W36-04, W5-01 | Done (init) — `POST /sys/init` one-time guard; rekey deferred to W36-17. | Fresh install: init creates root CA; second init rejected. |
| ~~**W38-13**~~ | §11.2, §11.6 | ~~CLI Viper config, completion, and secret masking~~ | docs | S | W20-01 | Done — Viper `~/.knxvault/config.yaml`, `completion`, `--show-secrets`. | Config sets default addr; get hides values by default. |
| ~~**W38-14**~~ | §7.1 | ~~Raft peer transport TLS~~ | security | M | W37-01 | Done — Dragonboat `MutualTLS` wired in `nodehost.go`; `knxvault_raft_tls_enabled` metric. | mTLS when all three `KNXVAULT_RAFT_MTLS_*` set. |
| ~~**W38-15**~~ | §7.4 | ~~API TLS bootstrap from vault PKI~~ | crypto | M | W37-01, W5-01 | Done — `POST /sys/tls/issue-listener` issues listener cert with auto-renew. | Listener cert auto-renews before expiry; documented bootstrap for K8s. |
| ~~**W38-16**~~ | §7.7 | ~~semgrep static analysis CI gate~~ | ci | S | W11-02 | Done — `.semgrep/knxvault.yml`, `make semgrep`. | semgrep fails on test rule violation; passes on clean tree. |
| ~~**W38-17**~~ | §8.4 | ~~OpenSSL circuit breaker~~ | crypto | S | W3-03 | Done — `breaker.go`, PKI 503 middleware, `knxvault_openssl_breaker_open`. | Simulated failure opens breaker; `/pki/issue` fast-fails. |
| ~~**W38-18**~~ | §9.5 | ~~Chaos and resilience test suite~~ | ci | L | W36-11 | Done (script) — `test/chaos/raft-pod-kill.sh`. | Chaos job: kill leader twice, cluster recovers. |
| ~~**W38-19**~~ | §12 | ~~LLD ↔ implementation traceability matrix~~ | docs | S | W36-22 | Done — `docs/product/lld-alignment.md`. | LLD §4–§8 mapped with code paths. |
| ~~**W38-20**~~ | §5.4 | ~~CORS and HTTP security headers middleware~~ | security | S | W8-01 | Done — `securityheaders.go` + CORS config. | Preflight OPTIONS + security headers; unit test. |
| ~~**W38-21**~~ | §6.5, §8.2 | ~~K8s startup probe and seccomp profile~~ | k8s | S | W28-02 | Done — `startupProbe`, `seccompProfile: RuntimeDefault`. | Cold start tolerates election. |
| ~~**W38-22**~~ | §8.4 | ~~Prometheus alerting rules~~ | docs | S | W22-01, W29-02 | Done — `deployments/prometheus/knxvault-alerts.yaml`. | Alert rules for leader loss, PKI errors, leases, breaker. |
| ~~**W38-23**~~ | §11.6 | ~~CLI example scripts~~ | docs | S | W20-01 | Done — `examples/cli/*.sh`. | Scripts documented for bootstrap, k8s login, backup. |
| ~~**W38-24**~~ | §7.2 | ~~CA key rotation and re-issuance workflow~~ | crypto | L | W5-01, W38-03 | Done (stub) — `POST /pki/ca/:id/rotate` creates successor CA. | Successor CA created; full re-issuance job deferred. |
| ~~**W38-25**~~ | §7.7, §9.5 | ~~Distroless/hardened production container image~~ | ci | M | W1-02 | Done (hardened multi-stage) — Dockerfile comments for distroless swap. | Multi-stage non-root image; OpenSSL via bookworm-slim runtime. |

> **Tier F sequencing:** **W38-01–W38-04** (API completeness) parallel with **W36-05**. **W38-05**, **W38-21** (K8s hardening) after **W28-02**. **K8s secret delivery → Tier G (W39)** before **W38-07**. **W38-14–W38-15** after **W37-01**. **W38-19** can start immediately and updated continuously. **W38-22** after metrics stable (**W29-02**).

### Tier A — Security blockers (do first)

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W36-01**~~ | ~~Fail closed on K8s login without JWT validation~~ | security | S | W7-03 | Done — `LoginKubernetes` rejects unvalidated login when Raft enabled; `KNXVAULT_K8S_AUTH_INSECURE` dev-only bypass. | Unit test: production mode + `POST /auth/kubernetes` → `401`. |
| ~~**W36-02**~~ | ~~Kubernetes TokenReview authentication~~ | auth | M | W36-01 | Done — `internal/infra/k8s/tokenreview.go`, wired in `internal/app/deps.go`. HS256 + `KNXVAULT_JWT_SECRET` dev-only fallback. | Fake TokenReview tests pass; `docs/architecture/security-model.md` updated. |
| ~~**W36-03**~~ | ~~ServiceAccount binding on roles~~ | auth | M | W36-02 | Done — `bound_service_account_names` / `bound_service_account_namespaces` on `Role`; enforced after TokenReview. | Matching SA → token; wrong SA/namespace → `403`. |
| ~~**W36-04**~~ | ~~Require master key when Raft enabled~~ | security | S | W3-01, W26-01 | Done — `NewDependencies` fails startup when Raft enabled without master key. | `deps_test.go`; documented in `docs/installation/configuration.md`. |
| ~~**W36-05**~~ | ~~Atomic KV write in Raft state machine~~ | storage | M | W25-01 | **Hint:** Race in `internal/engine/secrets/kvv2.go` — `NextVersion` then `SaveVersion` are **two** Raft ops; `OpSecretNextVersion` is read-only (`internal/raft/commands.go:73`). Add `secret.put` command: allocate version + CAS check + save inside `internal/raft/store.go:Handle` in one `Update`. Dragonboat repo: single `Propose` from `internal/repository/dragonboat/repo.go`. Deprecate split path or retry on `version already exists`. | Done — `OpSecretPut`, `PutAtomic`, concurrent put test in `store_test.go`. |

### Tier B — Raft correctness & HA confidence

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W36-06**~~ | ~~Include audit log in Dragonboat snapshots~~ | storage | M | W25-01 | Done — `ExportSnapshot(true)` in `statemachine.go`; unit + 3-node integration tests; `docs/storage/dragonboat.md`. | SaveSnapshot → RecoverFromSnapshot preserves audit entries. |
| ~~**W36-07**~~ | ~~Validate snapshot before `snapshot.import`~~ | storage | S | W27-01 | Done — `ValidateSnapshot` in `BackupService.Restore` and `Store.ImportSnapshot`; extended CA/PKI/RBAC/issued-cert/audit-chain checks. | Unit tests in `internal/backup/validate_test.go`. |
| ~~**W36-08**~~ | ~~Consistent backup export (single Raft read)~~ | storage | M | W27-01 | Done — `OpExportSnapshot`, `Client.ExportSnapshot`, `BackupService` atomic path; `TestExportSnapshotConsistentGraph`. | Atomic export self-consistent across entity types. |
| ~~**W36-09**~~ | ~~Align leader status with live Raft role~~ | k8s | S | W26-02 | Done — `Dependencies.IsLeader()` uses live `raft.Client.IsLeader()`; `internal/raft/leader_test.go`. | After forced leader step-down, `/health` `leader` and Prometheus gauge agree within one heartbeat RTT. |
| ~~**W36-10**~~ | ~~Dragonboat repository adapter tests~~ | ci | M | W26-01 | Done — `internal/repository/dragonboat/repo_test.go`. | `go test ./internal/repository/dragonboat/...` passes; covers save/get/list for CA and secret repos. |
| ~~**W36-11**~~ | ~~Raft leader failover integration test~~ | ci | M | W28-01 | Done — `TestRaftLeaderFailover` in `test/integration/raft_test.go` (30s window). | Failover test in `make test-integration`. |
| ~~**W36-12**~~ | ~~HTTP API integration tests with Raft enabled~~ | ci | M | W26-01, W36-11 | Done — `api_raft_test.go`: KV, backup, PKI, `/ready` with Raft deps. | PKI + KV round-trip with `RAFT_ENABLED=true`. |

### Tier C — Auth, tokens & RBAC polish

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W36-13**~~ | ~~Persist client tokens in Raft~~ | auth | L | W25-02, W36-02 | Done — `token.save/get/revoke/list` Raft commands; `TokenRepository` + `TokenStore.SetRepository`; wired in `deps.go`. TTL cleanup job deferred. | `TestTokenStoreReplicated` + memory/dragonboat repos. |
| ~~**W36-14**~~ | ~~Wire `namespace` RBAC condition~~ | auth | S | W13-01 | Done — `X-KNX-Namespace` header in auth middleware; `evaluator_test.go` + `middleware/auth_test.go`. | Policy with `namespace: prod` denies request without header; allows with `X-KNX-Namespace: prod`. |
| ~~**W36-15**~~ | ~~Fix `knxvault_active_leases` metric semantics~~ | docs | S | W15-02 | Done — `LeaseRepository.CountActive`, leader tick gauge; `docs/metrics.md`. | Metric reflects active leases; increments on creds generate, decrements on expire/revoke. |
| ~~**W36-16**~~ | ~~Leader election loop health & job gating~~ | k8s | S | W26-02 | Done — `knxvault_leader_election_running`, `/ready` check, job double-check on leader loss. | Kill leader election goroutine in test → `/ready` not ready; jobs do not run on follower. |

### Tier D — Features documented but missing

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W36-17**~~ | ~~Master key rotation API~~ | crypto | L | W3-02, W36-04 | Done — `internal/crypto/keyring.go`, `POST /sys/rotate-master-key`, re-encrypt job, CLI `sys rotate-master-key`, `docs/product/tier-b-production.md`. | Rotate + transition + CLI. |
| ~~**W36-18**~~ | ~~Managed database credentials execution mode~~ | crypto | L | W12-01 | Done — `execution_mode: managed`, KV `connection_url`, SQLite executor + unit test; `docs/deploy/database-credentials.md`. | Managed role executes creation/revocation SQL. |
| ~~**W36-19**~~ | ~~Return revocation SQL on lease revoke (client mode)~~ | api | S | W12-01 | Done — `revocation_statements` in `PUT /secrets/database/revoke/:id` response. | `PUT /secrets/database/revoke/:id` returns SQL strings when role defines them. |
| ~~**W36-20**~~ | ~~Wire `EngineRegistry` at startup~~ | api | S | W6-01 | Done — KV + database engines registered in `internal/app/deps.go`. | Registry lists 2 engines; no behavior change for existing API. |
| ~~**W36-21**~~ | ~~CLI parity for Day-2 operations~~ | docs | M | W20-01 | Done — policies, roles, audit export, database ops, `sys rotation-run`; `docs/cli/reference.md`. | Each documented CLI command in LLD §11 has working cobra subcommand. |
| ~~**W36-22**~~ | ~~LLD / security-model doc reconciliation~~ | docs | S | W36-01, W36-02, W36-04 | Done — `docs/product/lld-alignment.md`, `docs/integration/kubernetes-native.md` status matrix updated. | No doc claims production feature that code lacks without "planned" tag. |

### Tier E — Deferred alongside Phase 5

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W36-23**~~ | ~~Dynamic Raft cluster membership~~ | storage | XL | W28-02 | Done — `Client.AddNode`/`RemoveNode`, `POST /sys/raft/*`, `docs/operations/runbooks/scaling.md`. | API + runbook for expand/shrink. |
| ~~**W36-24**~~ | ~~Vault seal / unseal operational mode~~ | security | L | W36-17 | Done — `SealState`, `SealGuard` middleware, `POST /sys/seal`/`unseal`, CLI, `KNXVAULT_UNSEAL_KEY`. | Seal blocks writes; unseal restores. |

> **Phase 5 dependency note:** **W37-01** supersedes **W34-01** (mTLS) in priority. **W32-**\* (multi-tenancy) should follow **W37-03** / **W36-14**. **W36-13** (token persistence) should precede **W34-02** (client cert issuance).

---

## Phase 5 — Ecosystem (planned)

High-level scope from LLD §9.4. Phase 3 is complete; Phase 4 hardening recommended first. Detailed design in [`docs/design/phase4-ecosystem.md`](design/phase4-ecosystem.md).

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| **W30-01** | Kubernetes Operator scaffold | k8s | L | W29 | kubebuilder project, CRD types for CA and policy resources. | CRDs apply cleanly; scaffold compiles. |
| **W30-02** | Operator reconciliation loop | k8s | L | W30-01 | Reconcile CRDs to KNXVault REST API with status conditions. | Create CA via CRD → visible in API; e2e test passes. |
| **W31-01** | OpenSSL engine abstraction | crypto | M | W3-03 | **Tier P:** **P2** week 5–6 ([prospect gate](#tier-p--prospect-poc-immediate-july-2026-enterprise-memorandum)). **Gap:** PKI engine calls `openssl.Wrapper.SafeExec` directly — no pluggable backend for HSM or native `crypto/x509` ([ADR-0002](adr/0002-openssl-cli-crypto-backend.md) Phase 4). **Hint:** Define `internal/crypto/pki/backend.go` interface: `GenerateKey`, `CreateCSR`, `SignCertificate`, `GenerateCRL`, `SignOCSP` with implementations `opensslBackend` (wraps existing `SafeExec`), `nativeBackend` (stub until **W41-08**), `engineBackend` (PKCS#11 via **W31-02**). Inject via `pkiengine.NewEngine(backend, ...)` in `internal/app/deps.go`. Config: `KNXVAULT_PKI_BACKEND=openssl\|native\|pkcs11`. Unit tests with `mockBackend` recording calls; no subprocess in default unit tests. Prerequisite for **W41-08–W41-10** and **LT-07** FIPS engine path. | Mock backend passes full PKI integration suite; switching backend is config-only; OpenSSL remains default. |
| **W31-02** | PKCS#11 HSM integration (PKI signing keys) | crypto | L | W31-01 | **Gap:** CA private keys are software-generated and envelope-encrypted in Raft — no HSM integration for signing operations. **Scope ([ADR-0006](adr/0006-seal-unseal-strategies.md)):** PKI keys only — distinct from **W31-03** master key wrap. **Hint:** Implement `engineBackend` using OpenSSL `-engine pkcs11` (or OpenSSL 3 `-provider` when **W31-01** abstraction supports it) with config `KNXVAULT_PKCS11_MODULE`, `KNXVAULT_PKCS11_SLOT`, `KNXVAULT_PKCS11_PIN` (pin from env, never in Raft). Root CA `CreateRoot` generates key on-token; only cert PEM stored in Raft. Add SoftHSM2 dev setup in `scripts/sofhsm-setup.sh` and CI optional job. Document in `docs/operations/hsm-pki.md`. | Root CA created on SoftHSM; issue leaf signs on HSM; key never in `PrivateKeyEnc`; audit `pki.hsm.sign`. |
| **W31-03** | HSM-wrapped master key (envelope root) | crypto | L | W3-01, W31-01 | **Gap:** Master key is software-loaded from env/file ([ADR-0003](adr/0003-envelope-encryption.md) follow-up). **Decision ([ADR-0006](adr/0006-seal-unseal-strategies.md)):** Master key material wrapped on HSM or PKCS#11 token — separate from **W31-02** PKI signing. **Hint:** `internal/crypto/masterkey/hsm.go` — unwrap master key via PKCS#11 `C_Decrypt` or vendor KMS API at startup; plaintext master in mlocked buffer (**W41-01**) only for process lifetime. Config: `KNXVAULT_MASTER_KEY_SOURCE=hsm`, `KNXVAULT_PKCS11_MASTER_KEY_LABEL`. Never persist unwrapped master in Raft. Rotation: `POST /sys/rotate-master-key` re-wraps on HSM. Document vs cloud KMS (**LT-14**) choice matrix. | Cluster starts with HSM-wrapped master; no `KNXVAULT_MASTER_KEY` in env; unwrap failure fails closed. |
| **W32-01** | Multi-tenancy policy model | auth | M | W13-01 | Namespace-scoped policy isolation. | Cross-tenant access denied in tests. |
| **W32-02** | Tenant-aware API enforcement | api | M | W32-01 | Optional `X-KNX-Namespace` header enforcement. | Integration tests for tenant boundaries. |
| **W33-01** | Redis read cache | storage | M | W26 | Cache public CA material, CRLs, policies. | Cache hit metrics; fallback on miss. |
| **W33-02** | Cache invalidation on write | storage | S | W33-01 | Invalidate cache entries on Raft commit. | Write → read sees fresh data. |
| **W34-01** | Server mTLS | security | M | W5-03 | TLS with client certificate requirement on secured routes. | mTLS handshake test; opt-in flag. |
| **W34-02** | Client cert issuance API | security | M | W34-01 | PKI role for API consumer certificates. | Issue + authenticate with client cert. |
| **W35-01** | DR automation | ops | L | W27 | Cross-cluster backup replication and failover runbook. | DR drill documented and tested. |
| **W35-02** | Compliance audit packs | docs | M | W14 | Exportable audit bundles for compliance evidence. | Pack generation CLI command. |

---

## Long-term future

Deferred packaging, cloud-provider integrations (AWS/GCP/Azure KMS, AWS IAM dynamic secrets), and ecosystem work — not scheduled for Tier 0 / Phase 4–5 near-term delivery. Revisit after **W37** checklist items, **W36** hardening, and **Tier I** v1.0 blockers stabilize.

| Item | Area | Rationale |
|------|------|-----------|
| **Helm chart** | k8s | Deferred as **LT-03**. Near-term: raw manifests in `deployments/k8s/` (**W28-02**). |
| **Cloud dynamic secrets (AWS IAM)** | crypto | Deferred as **LT-02**. Near-term: database dynamic engine + OIDC auth. |
| Helm hooks (pre-upgrade backup) | k8s | Depends on **LT-03** Helm chart. |
| Grafana dashboards bundled in chart | docs | Depends on **LT-03** Helm chart + W10 metrics. |
| gRPC API, Web UI, OPA integration | api | **LT-04–LT-06** (LLD §10.3). |
| FIPS OpenSSL, Falco rules | security | **LT-07–LT-08** (LLD §7.6–7.7); seccomp hardening **W41-13**. |
| Cloud KMS auto-unseal (AWS/GCP/Azure) | crypto | **LT-14**, **LT-15**; near-term: sealed K8s Secrets. |
| Prospect POC immediate (memorandum) | security | [**Tier P**](#tier-p--prospect-poc-immediate-july-2026-enterprise-memorandum) — supersedes until exit. |
| Shamir / dual-mode unseal, native PKI | crypto | **Tier P** then **W41-14**; [ADR-0006](adr/0006-seal-unseal-strategies.md). |
| HSM master key wrap | crypto | **W31-03** (Phase 5); PKI HSM **W31-02**. |
| MkDocs / GitHub Pages publishing | docs | **LT-11** (LLD §12.1). |
| Performance benchmarking suite | ci | **LT-12** (LLD §9.5); gates **W41-09** native PKI parity. |

### Long-term backlog (detailed)

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| **LT-01** | Terraform provider | docs | L | LT-03, Phase 5 stable | **Gap:** LLD §9.4 / §12.2.4 Terraform provider; no IaC. **Hint:** `terraform-provider-knxvault/` with `hashicorp/terraform-plugin-framework`. Resources: `knxvault_kv_secret`, `knxvault_policy`, `knxvault_pki_root` (data). Auth via `KNXVAULT_TOKEN`. `docs/integration/terraform.md`. Defer until **LT-03** (Helm), **W36-02** (TokenReview), and API surface stable (**W38-01**). | `terraform apply` creates KV + policy; destroy removes. CI acceptance test. |
| **LT-02** | Cloud dynamic secrets engine (AWS IAM scaffold) | crypto | XL | W37-02, W36-20 | **Gap:** LLD §9.4 “Advanced dynamic secret engines (AWS, cloud OAuth)”; only DB engine exists. **Hint:** `internal/engine/secrets/aws/` + `POST /secrets/aws/creds/:role`; STS `AssumeRole` via **W37-02** OIDC. Register in **W36-20** `EngineRegistry`. **No near-term impact on vanilla K8s/KubeVirt** — use KV + database engine instead. | Temporary IAM creds issued; lease documented; LocalStack or sandbox test. |
| **LT-03** | Helm chart (production install) | k8s | M | W28-02, W37-01 | **Gap:** LLD §1.2, §6.1, §6.6 Helm-first deployment; only `deployments/helm/.gitkeep` + raw manifests. **Hint:** `deployments/helm/knxvault/` per LLD §6.1: `values.yaml` (`raft.*`, `persistence`, `tls`), StatefulSet from `statefulset.yaml`, Service/Ingress templates. Hooks → **LT-09**. Defer until **W37-01** TLS and **W38-05** PDB/NetPol patterns proven in raw manifests. | `helm install` 3-node Raft; README + `docs/deploy/kubernetes.md` updated. |
| **LT-04** | gRPC API alongside REST | api | L | Phase 5 stable | **Gap:** LLD §10.3 gRPC for service mesh. **Hint:** `api/proto/knxvault/v1/` with grpc-gateway or parallel handlers; mTLS from **W37-01**. | grpcurl list/get KV works; REST unchanged. |
| **LT-05** | Web UI admin console | docs | XL | Phase 5 stable | **Gap:** LLD §10.3 optional React/Vue UI. **Hint:** Separate repo `knxvault-ui/` consuming OpenAPI; OIDC login (**W37-02**). | Read-only secrets/PKI view; no secrets in browser storage. |
| **LT-06** | OPA / Gatekeeper policy integration | auth | L | W32-01 | **Gap:** LLD §10.3 “Policy as Code” with OPA. **Hint:** Export KNXVault policies to Rego bundle; optional `POST /sys/policy/validate` delegating to OPA sidecar. | Deny rule in OPA blocks matching KNXVault policy eval. |
| **LT-07** | OpenSSL FIPS mode | security | M | W31-01 | **Gap:** LLD §7.6 FIPS via OpenSSL config. **Hint:** `KNXVAULT_OPENSSL_FIPS=true` sets `OPENSSL_FIPS` or FIPS config path in `internal/crypto/openssl/wrapper.go`; document compliance limits. | FIPS-enabled image issues cert in test harness. |
| **LT-08** | Falco rules for OpenSSL anomalies | security | S | W10-01, W41-13 | **Gap:** LLD §7.7 Falco rules; detection-only today. **Hint:** `deployments/falco/knxvault-rules.yaml` with rules: (1) `spawned_process` where `proc.name=openssl` and `proc.cwd` not matching `knxvault-openssl-*`; (2) `openssl` exec by uid ≠ 65532; (3) `openssl` with `-engine` or `-provider` args (should never occur post-validation). Pair with **W41-13** seccomp profile — Falco alerts when seccomp denies unexpected syscall. Document install in `docs/operations/runbooks/falco-openssl.md`. | Falco alerts in test when exec escapes pattern; false-positive rate &lt;1/day in steady-state PKI load test. |
| **LT-09** | Helm pre-upgrade backup hooks | k8s | S | LT-03, W27-01 | **Gap:** LLD §6.6 upgrade safety. **Hint:** Helm `pre-upgrade` Job calling `POST /sys/backup` with RBAC token from Secret. | `helm upgrade` creates backup Secret before rollout. |
| **LT-10** | Multi-region CA federation | crypto | XL | W35-01 | **Gap:** LLD §10.3 multi-region hierarchy. **Hint:** Cross-cluster CA trust bundle replication via encrypted backup sync; design doc only initially. | Design doc + PoC two-cluster trust. |
| **LT-11** | MkDocs / GitHub Pages documentation site | docs | M | W38-19 | **Gap:** LLD §12.1 version-controlled docs published via MkDocs or GitHub Pages; repo is Markdown-only with no site build. **Hint:** `mkdocs.yml` + Material theme; CI deploy to GitHub Pages on release tag; OpenAPI + CLI refs linked. Defer until **W38-19** traceability matrix stabilizes. | `mkdocs serve` renders `/docs/`; release tag publishes public site. |
| **LT-12** | Performance benchmarking suite | ci | M | W29-02, W41-08 | **Gap:** LLD §9.5 “performance benchmarking” cross-cutting activity; no `bench/` or SLO targets; enterprise review cites subprocess overhead on PKI. **Hint:** `test/bench/` with `testing.B` for KV put/get, Raft propose, OpenSSL issue, native PKI issue (**W41-08**); optional `ghz` for HTTP load; record baselines in `docs/engineering/performance.md`. Define SLO targets: KV put p99 &lt;50ms (single-node), PKI issue p99 &lt;2s (OpenSSL), &lt;500ms (native target). CI stores bench JSON artifacts; regression &gt;20% fails advisory gate. | CI stores bench results; native vs OpenSSL comparison documented; regression &gt;20% fails advisory gate. |
| **LT-13** | Pluggable storage backend (external DB) | storage | XL | W29-01 | **Gap:** Enterprise review requests Aurora/Consul-style storage; KNXVault is Dragonboat-only ([ADR-0001](adr/0001-dragonboat-storage-backend.md)). **Not planned for near-term** — document as explicit non-goal unless customer-funded. **Hint:** If pursued: design doc `docs/design/external-storage-evaluation.md` with rejection rationale; optional read-only analytics replica only (not primary write path). | ADR updated with decision; no code unless ADR accepted. |
| **LT-14** | Cloud KMS auto-unseal — AWS | crypto | L | W36-24, W41-01, Phase 5 stable | **Gap:** `KNXVAULT_MASTER_KEY` must be supplied as plaintext env/file at bootstrap; no envelope unwrap via cloud KMS ([ADR-0003](adr/0003-envelope-encryption.md) follow-up). **Deferred** — KNXVault is Kubernetes-native first; cloud-provider SDKs and IRSA coupling are not near-term. **Hint:** New package `internal/crypto/kms/aws/` using AWS SDK v2 `kms.Decrypt` with IRSA credentials (`STS web identity` from projected SA token). Config: `KNXVAULT_KMS_PROVIDER=aws`, `KNXVAULT_KMS_KEY_ID`, `KNXVAULT_KMS_ENCRYPTED_MASTER_KEY` (base64 ciphertext blob). Startup flow in `internal/app/deps.go`: if KMS config present, decrypt master key in-memory only — never log or persist plaintext. Support key rotation via `KNXVAULT_KMS_KEY_ID` alias. Add LocalStack integration test in `test/integration/kms_aws_test.go` (optional CI gate). Document IRSA trust policy in `docs/deploy/kubernetes.md`. **Near-term:** sealed K8s Secrets, External Secrets Operator, or manual key injection per [operator-security.md](operations/operator-security.md). | Pod with IRSA decrypts master key without `KNXVAULT_MASTER_KEY` env; Raft cluster starts; decrypt failure fails closed; audit `kms.unseal` (no key material). |
| **LT-15** | Cloud KMS auto-unseal — GCP and Azure | crypto | L | LT-14 | **Gap:** AWS-only KMS leaves GCP Workload Identity and Azure Key Vault customers on manual key injection. **Deferred** alongside **LT-14**. **Hint:** `internal/crypto/kms/gcp/` — `cloud.google.com/go/kms/apiv1` `Decrypt` with Workload Identity; `internal/crypto/kms/azure/` — `azkeys` client with federated credential. Unified interface `internal/crypto/kms/provider.go` with `Decrypt(ctx, ciphertext []byte) ([]byte, error)` selected by `KNXVAULT_KMS_PROVIDER` (`aws` \| `gcp` \| `azure`). Shared config validation in `internal/config/kms.go`. | GCP + Azure decrypt paths pass integration tests (emulator or mock); single provider active per process. |