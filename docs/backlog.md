# KNXVault Backlog

Actionable backlog derived from [`docs/lld.md`](lld.md) (Phase 1 / MVP). Items are **topologically sorted by dependency** — implement in listed order within each phase.

**Legend**

| Field | Meaning |
|-------|---------|
| **ID** | `W#-##` = Phase 1 work item (dependency order) |
| **Effort** | S (< 1 day) · M (1–3 days) · L (3–7 days) · XL (> 1 week) |
| **Area** | ci · crypto · storage · api · auth · k8s · docs · security |
| **Depends on** | Prior backlog IDs that must be complete first |

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
| ~~**W4-02**~~ | ~~PostgreSQL schema migrations~~ | storage | S | W4-01 | Initial schema per LLD §4.D.1. | Done — `migrations/001_init.sql`, embedded via `migrations/embed.go`, runner in `internal/repository/postgres/migrate.go`. |
| ~~**W4-03**~~ | ~~Repository interfaces~~ | storage | S | W4-01 | CA, Secret, Audit interfaces per LLD §4.D.3. | Done — `internal/repository/interfaces.go`. |
| ~~**W4-04**~~ | ~~PostgreSQL repository implementations~~ | storage | M | W4-02, W4-03 | `pgxpool` repositories for cas, secret_versions, audit_logs. | Done — `internal/repository/postgres/*_repository.go`, pool + migrate. |
| ~~**W4-05**~~ | ~~Repository unit & integration tests~~ | storage | M | W4-04 | In-memory fakes + optional Postgres integration tests. | Done — `internal/repository/memory/*`, `integration_test.go` (skips without `KNXVAULT_TEST_DATABASE_URL`). |
| ~~**W4-06**~~ | ~~Database bootstrap wiring~~ | storage | S | W4-04 | Connect pool, auto-migrate, readiness check. | Done — `KNXVAULT_DATABASE_URL`, `KNXVAULT_AUTO_MIGRATE`, `/ready` pings DB when configured. |
| ~~**W5-01**~~ | ~~PKI engine (root CA)~~ | crypto | M | W3-03, W4-04 | Create self-signed root CA via OpenSSL, encrypt key material. | Done — `internal/engine/pki/engine.go` `CreateRoot` + tests. |
| ~~**W5-02**~~ | ~~PKI engine (intermediate CA)~~ | crypto | M | W5-01 | Sign intermediate CAs chained to parent. | Done — `CreateIntermediate` with parent key decryption + signing. |
| ~~**W5-03**~~ | ~~PKI engine (leaf issuance)~~ | crypto | M | W5-01 | Issue leaf certificates with SAN support. | Done — `IssueCertificate` with DNS SAN via OpenSSL extfile. |
| ~~**W5-04**~~ | ~~PKI revocation & CRL~~ | crypto | M | W5-01, W4-04 | Revoke serials, generate PEM CRL. | Done — `migrations/002_revocation.sql`, `RevocationRepository`, `Revoke` + `GenerateCRL`. |
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
| ~~**W11-01**~~ | ~~Integration test suite~~ | ci | M | W9-01, W4-05 | Compose-based API + Postgres tests. | Done — `test/integration/*`, `make test-integration`, `docker-compose.test.yml`. |
| ~~**W11-02**~~ | ~~Security scan gates (gosec)~~ | security | S | W1-02 | Add gosec to Makefile / `make all`. | Done — `make gosec`, `.gosec.json`, included in `make all`. |

> **Note:** Helm chart deferred to [Long-term future](#long-term-future) — Phase 1 uses Dockerfile + raw K8s manifests only.

---

## Phase 2 — Enterprise (in progress)

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W12-01**~~ | ~~Dynamic DB credentials engine~~ | crypto | M | W6-01, W4-04 | Database credentials engine with lease lifecycle and rotation. | Done — `internal/engine/secrets/database/`, `leases` + `database_roles` tables, `/secrets/database/*` API, lease renew/revoke, background cleanup job. |
| ~~**W12-02**~~ | ~~Lease repository & migration~~ | storage | S | W12-01 | Persist leases and database role configuration. | Done — `migrations/003_phase2.sql`, postgres + memory repositories. |
| ~~**W13-01**~~ | ~~RBAC conditions evaluator~~ | auth | M | W7-01 | Policy conditions (`ip_cidr`, `time_after`/`time_before`, `path_prefix`, `namespace`). | Done — `internal/auth/evaluator.go` + tests, wired into auth middleware. |
| ~~**W13-02**~~ | ~~Persisted policies & roles~~ | auth | M | W13-01 | Policy/role CRUD with DB persistence and runtime reload. | Done — `policies` + `roles` tables, `/sys/policies` + `/sys/roles` API. |
| ~~**W14-01**~~ | ~~Audit export API~~ | auth | M | W7-04 | Export audit logs with hash-chain head and HMAC signature. | Done — `GET /audit/export`, details included in hash payload, `KNXVAULT_AUDIT_SIGNING_KEY`. |
| ~~**W14-02**~~ | ~~Audit chain verification~~ | auth | S | W14-01 | Verify hash chain integrity and signature. | Done — `POST /audit/verify`, `internal/audit/service.go` Export/Verify. |
| ~~**W15-01**~~ | ~~Kubernetes Lease leader election~~ | k8s | M | W9-02 | HA mode with coordination.k8s.io Lease (lightweight HTTP client). | Done — `internal/infra/k8s/leader.go`, `KNXVAULT_HA_ENABLED`, leader status in `/ready`. |
| ~~**W15-02**~~ | ~~Background jobs (lease cleanup, CRL refresh)~~ | k8s | M | W15-01, W12-01, W5-04 | Leader-only periodic jobs for lease cleanup and CRL refresh. | Done — `internal/app/jobs.go`, ConfigMap intervals, 3-replica Deployment + Lease RBAC. |

| ~~**W16-01**~~ | ~~Certificate renewal automation~~ | crypto | M | W5-03, W15-02 | TTL-based renewal API and background job with grace window. | Done — `issued_certificates` table, `POST /pki/renew`, `auto_renew` on issue, leader job. |
| ~~**W17-01**~~ | ~~OCSP responder (basic)~~ | crypto | M | W5-04 | DER OCSP endpoint with good/revoked status. | Done — `POST /pki/ocsp/:id`, `internal/engine/pki/ocsp.go` + tests. |
| ~~**W18-01**~~ | ~~Secrets injection render API~~ | k8s | M | W6-01 | Sidecar/init-container render endpoint. | Done — `POST /inject/render`, `internal/inject/`, sidecar example manifest. |
| ~~**W18-02**~~ | ~~CSI provider scaffolding~~ | k8s | S | W18-01 | CSI provider interface and K8s DaemonSet template. | Done — `internal/inject/csi/`, `deployments/csi/`, `docs/deploy/secrets-injection.md`. |
| ~~**W19-01**~~ | ~~Rate limiting~~ | security | M | W8-04 | Per-token/IP token-bucket rate limiting on secured routes. | Done — `internal/api/middleware/ratelimit.go`, `knxvault_rate_limited_total` metric. |
| ~~**W19-02**~~ | ~~Request signing~~ | security | M | W7-05 | Optional HMAC request signatures with timestamp skew check. | Done — `internal/api/middleware/signing.go`, `KNXVAULT_REQUEST_SIGNING_*` config. |

### Phase 2 — remaining (outline)

- CLI tool (`knxvault`)
- Backup & restore procedures
- Improved observability (tracing, Grafana dashboards)

---

## Phase 3 — Ecosystem (outline)

High-level scope from LLD §9.4; items not yet broken down.

- Terraform provider
- Kubernetes Operator (CRD-based CA/role management)
- HSM support via OpenSSL engine
- Multi-tenancy, Redis cache, full mTLS, DR automation

---

## Long-term future

Deferred packaging and ecosystem work — not scheduled for Phase 1 MVP.

| Item | Area | Rationale |
|------|------|-----------|
| **Helm chart** | k8s | Install UX and values templating deferred until core API, auth, and raw K8s deploy path are stable. Target: post–Phase 1 (Phase 2+). See LLD §6.1 for intended chart structure. |
| Helm hooks (pre-upgrade backup) | k8s | Depends on Helm chart. |
| Grafana dashboards bundled in chart | docs | Depends on Helm chart + W10 metrics. |