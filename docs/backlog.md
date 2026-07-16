# KNXVault Backlog

Actionable backlog derived from [`docs/lld.md`](lld.md). Items are **topologically sorted by dependency** — implement in listed order within each phase.

**Current focus (2026-07-16):** **P0 — replace cert-manager** with a first-class KNXVault Kubernetes operator (CRD automation: CA + Certificate → `kubernetes.io/tls` Secret). Prefer KNXVault PKI + operator for **all** in-cluster / internal-CA TLS use cases; keep cert-manager only as optional legacy (ACME/public CAs out of scope). Remaining Phase 5 work also includes tenant depth, HSM, mTLS polish. Long-term packaging and cloud engines remain [LT-*](#long-term-future).

**Legend**

| Field | Meaning |
|-------|---------|
| **ID** | `W#-##` = work item (dependency order within phase) |
| **Priority** | **P0** (current focus) · **P1** (next) · **P2** (later) — omit when complete |
| **Status** | **Complete** · **Partial** · **Not started** (core audit 2026-07-02; P0 operator program added 2026-07-16) |
| **Effort** | S (< 1 day) · M (1–3 days) · L (3–7 days) · XL (> 1 week) |
| **Area** | ci · crypto · storage · api · auth · k8s · docs · security |
| **Depends on** | Prior backlog IDs that must be complete first |

**Phase 4–5 status summary** (verified against codebase + P0 operator expansion)

| Status | Count | IDs |
|--------|-------|-----|
| Complete (Tier 0 / Phase 4 core) | 29 | W37-04, W37-06, W37-09, W38-15, W39-01–08, W40-01–03, W40-08, W36-09, W36-10, W36-14, W36-15, W36-16, W36-20, W36-21, W36-22 |
| Complete (Phase 5 / Tiers I–L) | 33 | W36-19, W41-01–04, W41-06–10, W42-01–08, W43-01–08, W44-01–04, W32-02, W31-01, W40-04–07 |
| Partial | 11 | W30-01, W32-01, W32-03–05, W33-01–02, W34-01–02, W35-01–02 |
| Not started (P0 operator program) | 9 | **W30-02–W30-10** |
| Not started (other) | 1 | W31-02 |
| Long-term only | 14 | LT-01–LT-14 |

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
| ~~**W37-04**~~ | NHI / AI agents | ~~AI agent scoped auth & delegation~~ | auth | M | W37-02, W37-03 | Done — `POST /auth/agent/delegate`, `allowed_actions[]`, `agent_id` RBAC condition, path-prefix enforcement in `internal/auth/agent.go` + `Authorize`. | Parent CI token delegates 15m agent token; agent cannot access paths outside prefix. Delegation audited with parent→child link. |
| ~~**W37-05**~~ | Automated rotation | ~~Scheduled KV secret rotation~~ | crypto | M | W36-05, W36-17 | Done — `RotationPolicy` Raft entity, `runKVRotation` job, `PUT /sys/kv-rotation`, `random_password` generator. | Leader-only rotation + `secret.rotate` audit. |
| ~~**W37-06**~~ | Automated rotation | ~~End-to-end rotation orchestration~~ | crypto | L | W37-05, W36-18 | Done — `POST /sys/rotation/run`, `internal/service/orchestration.go` (KV + DB + PKI), `internal/notify/webhook.go`, CLI `sys rotation-run`. | DB lease auto-renewed before TTL; KV rotated per W37-05; webhook receives event; audit trail links old→new version/lease. |
| ~~**W37-07**~~ | Exposure detection | ~~Secret exposure webhook & auto-remediation hooks~~ | security | L | W37-05, W36-17 | Done — `POST /sys/exposure/report` HMAC-signed, auto-revoke/rotate, `docs/integration/exposure-detection.md`. | Unsigned report rejected; webhook + remediation. |
| ~~**W37-08**~~ | Integrations | ~~Multi-language SDK via OpenAPI codegen~~ | docs | M | W40-03 | Superseded by Tier H [**W40-03–W40-07**](#tier-h--kubernetes-ecosystem-eso-cert-manager-sdks). Go reference: `pkg/client`. | — |
| ~~**W37-09**~~ | Checklist / docs | ~~Secrets manager capability matrix~~ | docs | S | W37-01–W37-07 | Done — `docs/product/secrets-manager-checklist.md` covers all criteria with code/doc references. | Matrix covers all 10 checklist items; no “implemented” without code or ADR reference. |

> **Tier 0 sequencing:** **W37-01** (TLS) + **W37-02** (OIDC) unblock most NHI/dynamic-cred work. **W37-07** (exposure) can start after rotation hooks (**W37-05**). **W37-08** (SDKs) after Tier A auth blockers (**W36-01–W36-04**). **At rest encryption** is already implemented (envelope + Raft); maintain via **W36-04**. Near-term K8s deploy: raw manifests (`deployments/k8s/`). **Helm** (**LT-03**), **Terraform** (**LT-01**), **AWS IAM** (**LT-02**) → [long-term future](#long-term-future).

### Tier G — Kubernetes-native consumption (CSI first) — **mostly shipped**

**Product direction:** KNXVault is a Kubernetes-native secrets platform — [**Secrets Store CSI Driver**](https://secrets-store-csi-driver.sigs.k8s.io/) integration is **first-class**. **Status (2026-07):** W39-01–W39-08 **complete**. Workloads mount secrets via `SecretProviderClass`; sidecar/init (**W18**) remain fallbacks. **Helm packaging** → LT-03; manifests in `deployments/csi/`.

| ID | LLD § | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|-------|------|--------|------------|-------------|---------------------|
| ~~**W39-01**~~ | §6.4 | ~~CSI provider gRPC server (`knxvault-csi`)~~ | k8s | L | W18-02, W36-02 | Done — `cmd/knxvault-csi/main.go`, gRPC in `internal/inject/csi/server.go`, `make build-csi`. | Provider registers with driver; `Mount` returns file objects for configured KV paths. |
| ~~**W39-02**~~ | §6.4, §4.C.1 | ~~Pod identity auth on CSI mount (no static tokens)~~ | auth | M | W39-01, W36-02, W36-03 | Done — SA JWT + TokenReview per mount; `csi.mount` audit via `POST /inject/csi/mount-audit` from provider. | Pod with bound SA mounts secret; wrong SA → mount fails; no long-lived token in provider pod. |
| ~~**W39-03**~~ | §6.4 | ~~`SecretProviderClass` schema and reference manifests~~ | k8s | S | W39-01 | Done — `deployments/csi/secretproviderclass-example.yaml`, `pod-example.yaml`; schema in `docs/deploy/secrets-injection.md`. | `kubectl apply` + example pod reads mounted file in kind cluster. |
| ~~**W39-04**~~ | §6.4 | ~~CSI provider DaemonSet, RBAC, and install runbook~~ | k8s | M | W39-01, W38-05 | Done — `deployments/csi/k8s-provider.yaml`, `rbac.yaml`, `docs/deploy/csi-install.md`. | Fresh kind cluster: driver + provider + example pod end-to-end per runbook. |
| ~~**W39-05**~~ | §6.4, §7.2 | ~~CSI secret rotation and driver reload~~ | k8s | M | W39-01, W37-05 | Done — `knxvault_csi_mount_rotations_total`, SPC rotation docs, Mount version detection. | KV version bump detected on remount. |
| ~~**W39-06**~~ | §6.4 | ~~Optional sync to native Kubernetes `Secret`~~ | k8s | S | W39-03 | Done — `secretObjects` in `deployments/csi/secretproviderclass-example.yaml`; etcd trade-off in `docs/deploy/csi-install.md`. | `secretObjects` creates synced Secret; envFrom works; doc warns about duplicate plaintext in etcd. |
| ~~**W39-07**~~ | §6.4, §9.5 | ~~CSI end-to-end integration test (kind)~~ | ci | M | W39-04 | Done — `scripts/test-csi-kind.sh` deploys driver/RBAC/provider; `test/integration/csi_test.go` asserts KV content + mount audit. | Script passes locally; documented in `docs/engineering/development.md`. |
| ~~**W39-08**~~ | §6.4, §12 | ~~Product docs — CSI as primary K8s integration~~ | docs | S | W39-03 | Done — CSI-first in `docs/deploy/secrets-injection.md`, `docs/integration/overview.md`, `docs/integration/kubernetes-native.md`. | New operator onboarding path leads with CSI; sidecar labeled fallback. |

> **Tier G sequencing:** **W39-01** after **W36-02** (TokenReview). **W37-01** (TLS) recommended before production in-cluster `vaultAddr`. **W39-03–W39-04** parallel once **W39-01** skeleton mounts. **W39-05** after **W37-05**. **W38-07** (mutating webhook) **defers** until Tier G baseline ships — webhook is convenience, not primary.

### Tier H — Kubernetes ecosystem (ESO, cert-manager, SDKs)

**Product direction:** Full Kubernetes-native surface in [`docs/integration/kubernetes-native.md`](integration/kubernetes-native.md). **ESO and cert-manager shipped (2026-07).** Remaining work: **multi-language SDKs** (W40-03–07).

| ID | Integration | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------------|-------|------|--------|------------|-------------|---------------------|
| ~~**W40-01**~~ | External Secrets Operator | ~~Native ESO `knxvault` provider~~ | k8s | L | W39-02, W36-03 | Done — `cmd/knxvault-eso`, `internal/eso/server.go`, `deployments/external-secrets/knxvault-eso-deployment.yaml`. | `ExternalSecret` creates/updates K8s `Secret`; refresh picks up new KV version. |
| ~~**W40-02**~~ | cert-manager | ~~cert-manager Issuer for KNXVault PKI~~ | crypto | L | W38-03, W36-02 | Done — Vault shim `internal/api/handlers/vaultcompat.go`; `deployments/cert-manager/clusterissuer-knxvault.yaml`. | `Certificate` resource becomes Ready; TLS Secret contains issued leaf + key. |
| ~~**W40-03**~~ | SDKs | ~~OpenAPI client generation pipeline~~ | docs | S | W8-03 | Done — `make generate-clients`, `make test-clients`, `make check-client-drift`, `clients/.openapi-sha256`. | `make generate-clients` produces Python/TS/Java/Rust trees. |
| ~~**W40-04**~~ | SDKs | ~~Python client (`clients/python`)~~ | docs | M | W40-03 | Done — `clients/python/examples/health_smoke.py`; stub tree compiles; `make generate-clients` for full OpenAPI codegen (requires Docker). | Smoke example runs against dev server. |
| ~~**W40-05**~~ | SDKs | ~~Node.js / TypeScript client (`clients/typescript`)~~ | docs | M | W40-03 | Done — `clients/typescript/examples/health_smoke.ts`; stub tree compiles. | Health smoke example passes. |
| ~~**W40-06**~~ | SDKs | ~~Java client (`clients/java`)~~ | docs | M | W40-03 | Done — `clients/java/examples/HealthSmoke.java`; stub tree compiles. | Example compiles and calls health. |
| ~~**W40-07**~~ | SDKs | ~~Rust client (`clients/rust`)~~ | docs | M | W40-03 | Done — `clients/rust/examples/health_smoke.rs`; stub tree compiles. | Example compiles and calls health. |
| ~~**W40-08**~~ | Docs | ~~Kubernetes-native integration matrix~~ | docs | S | W40-01 | Done — `docs/integration/kubernetes-native.md` lists six integrations with status and code paths. | All six integrations listed with code path or backlog ID. |

> **Tier H sequencing:** **W40-03** first (finish pipeline + CI). **W40-04–07** parallel after W40-03 generates client trees.

### Tier I — Policy engine (Vault/OpenBao parity)

**Status (2026-07-02):** Core policy engine **shipped** — capabilities, deny precedence, KV path-aware auth, glob patterns, includes/`policy_groups`, simulation API, operator guide, denial audit. **Remaining gap:** path-aware auth on **PKI/inject** routes (still coarse `RequirePermission`); HCL import lacks CLI; simulate endpoint lacks dedicated tests; no KV path ACL integration test.

| ID | Status | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|--------|-------|------|--------|------------|-------------|---------------------|
| ~~**W41-01**~~ | Complete | Path-aware authorization (KV, inject, PKI) | auth | M | W13-02, W36-14 | Done — `RequirePathCapability` on PKI CA/CRL routes; inject path checks in `handlers/inject.go`; KV uses `RequireKVAccess` + integration test `kv_pathauth_test.go`. | Policy `resources: ["secrets/kv/team-a/*"]` allows `GET /secrets/kv/team-a/x` and denies `team-b/x` in API integration test. |
| ~~**W41-02**~~ | Complete | Capability model (read / write / list / delete / sudo) | auth | M | W41-01 | Done — `internal/auth/capabilities.go`, `NormalizeCapabilities`, `sudo` on token create (`router.go`). | Policy with only `list` can call metadata/list endpoints but not `GET` secret values; `sudo` gates `POST /auth/token/create`. |
| ~~**W41-03**~~ | Complete | Default-deny and deny-precedence semantics | auth | S | W41-02 | Done — `AuthorizeDetailed` in `internal/auth/authz.go`; `TestDenyOverridesAllow` in `rbac_test.go`. | Deny policy on `secrets/kv/team-a/*` blocks even if another policy allows `secrets/*`. |
| ~~**W41-04**~~ | Complete | Policy simulation API | api | M | W41-02 | Done — `POST /sys/policy/simulate`, CLI `sys policy simulate`, `policy_simulate_test.go` (allow/deny/condition). | CLI `sys policy simulate` matches API; unit tests for allow/deny/condition cases. |
| ~~**W41-05**~~ | Complete | KV list vs read separation | api | M | W41-02 | Done — `KVCapability()` in `pathauth.go` maps list/metadata/versions → `list`, values → `read`. | Reader with `list` only sees paths/versions; `read` required for plaintext. |
| ~~**W41-06**~~ | Complete | Authorization denial audit | security | S | W41-01 | Done — `authz.denied` in `internal/api/middleware/authz_audit.go` with rate-limited denials. | Failed `Authorize` produces audit row; success unchanged. |
| ~~**W41-07**~~ | Complete | Policy operator guide & examples | docs | S | W41-02 | Done — `docs/architecture/policy-engine.md`; linked from `security-model.md`. | Examples cover team-scoped KV, PKI read-only, break-glass admin; linked from security-model. |
| ~~**W41-08**~~ | Complete | HCL policy import (Vault migration) | auth | L | W41-02 | Done — `hclimport.go`, `POST /sys/policies/:name/import`, CLI `sys policies import`, `pkg/client.ImportPolicyHCL`. | Sample Vault KV policy imports and enforces correctly on path-aware API. |
| ~~**W41-09**~~ | Complete | Glob path patterns (`*`, `**`, `?`) | auth | M | W41-01 | Done — `internal/auth/glob.go`, `MatchResource`, `TestGlobResourceMatch`. | Policy `secrets/kv/team-?/app-*` matches `team-a/app-config` and denies `team-b/other`; unit tests in `rbac_test.go`. |
| ~~**W41-10**~~ | Complete | Policy composition and reusable modules | auth | L | W41-02 | Done — `Policy.Includes`, `ResolvePolicyNames`, role `policy_groups` via `flattenRolePolicies`. | Role composes two policies; deny in one module overrides allow in another (**W41-03**); migration guide from flat policy lists. |

> **Tier I sequencing:** Finish **W41-01** (wire PKI/inject path auth + integration test). **W41-04** tests and **W41-08** CLI import are polish. **W32-**\* (multi-tenancy depth) follows **W41-01** + **W36-14**. **LT-06** (OPA) after **W41-04** and **W32-01**.

### Tier K — BFSI prospect gaps (auth audit, lockout, tenant depth)

**Source:** External BFSI prospect evaluation (2026-07). Confirms **controlled POC viability** (Raft, audit chain, PKI, K8s integrations) while flagging **production gaps** in policy engine maturity, authentication audit, and brute-force controls. Maps to [`docs/audit/formal-code-audit-2026.md`](audit/formal-code-audit-2026.md) and [`docs/product/bfsi-poc-traceability.md`](product/bfsi-poc-traceability.md).

**Gap summary**

| Prospect concern | Current state | Backlog |
|------------------|---------------|---------|
| Explicit deny precedence | **Complete** (`authz.go`, tests) | — |
| Declarative policy / globs / composition | **Complete** (includes, globs); HCL import **Partial** | **W41-08** |
| Tenant isolation end-to-end | **Partial** (tenant middleware + KV scoping) | **W32-03–05** |
| Authentication audit trail | **Partial** (K8s/OIDC login audit; export schema gaps) | **W43-01–02** |
| Login lockout / throttling | **Partial** (throttle + per-IP lockout on K8s/OIDC) | **W43-03–05** |
| ABAC / MFA / SAML | **Partial** (conditions + MFA); labels not wired live | **W44-01–02**, **LT-13–14** |

| ID | Status | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|--------|-------|------|--------|------------|-------------|---------------------|
| ~~**W43-01**~~ | Complete | Authentication audit events (login success/failure) | auth | M | W7-04 | Done — K8s/OIDC + `LoginWithTokenEndpoint` audits failures on `POST /auth/token`. | Failed K8s login (wrong SA) produces audit row with `status=failure`; success produces `status=success`; no token material in details. |
| ~~**W43-02**~~ | Complete | Audit schema enrichment for authn/authz | auth | M | W43-01 | Done — `Record()` populates `audit.Entry` auth fields; export DTO includes top-level `auth_method`, `source_ip`, `request_id`, etc. | Export row includes `request_id` matching `X-Request-ID`; SIEM forwarder sample updated in `docs/observability/audit-forwarding.md`. |
| ~~**W43-03**~~ | Complete | Login endpoint throttling and brute-force protection | security | M | W19-01 | Done — `AuthLoginThrottle`; `auth_throttle_test.go` verifies 429. | 429 after N failures/min/IP; legitimate SA login unaffected after window; unit + integration test. |
| ~~**W43-04**~~ | Complete | Identity lockout after repeated failed logins | security | M | W43-03 | Done — `auth.lockout` audit; `DELETE /sys/auth/lockout` (sudo); lockout on `POST /auth/token`. | Lockout blocks further login for 15m; admin clear via API or TTL expiry; documented break-glass. |
| ~~**W43-05**~~ | Complete | Token issuance rate limits | security | S | W19-01 | Done — `TokenCreateThrottle` on `POST /auth/token/create` and `POST /auth/agent/delegate`. | Exceeding limit returns 429; metric `knxvault_token_create_throttled_total`. |
| ~~**W43-06**~~ | Complete | OIDC config on `PUT /sys/roles` API | auth | S | W37-02 | Done — `dto.RoleRequest`/`RoleResponse` with `auth_method`, `oidc`, `require_mfa`; `handlers/policies.go`. | `PUT /sys/roles/oidc-app` with OIDC config round-trips; `POST /auth/oidc/oidc-app` works without manual Raft seeding. |
| ~~**W43-07**~~ | Complete | JWKS cache keyed by URL | auth | S | W37-02 | Done — per-URL LRU cache; `oidc_test.go` multi-IdP JWKS validation. | Two roles with different IdPs validate against correct keys; unit test in `oidc_test.go`. |
| ~~**W43-08**~~ | Complete | BFSI prospect evaluation response pack | docs | S | W43-01, W41-03 | Done — `docs/product/bfsi-prospect-response.md`. | Document linked from traceability matrix; includes Go/No-Go for POC vs production. |

> **Tier K sequencing:** **W43-01–02** (audit export schema) before POC sign-off. **W43-03–05** polish before internet-facing deploy. **W43-07** multi-IdP test.

### Tier L — P2 enterprise authz (ABAC, MFA, federation)

**Source:** Prospect P2 enhancements. Builds on **W13-01** conditions and **W37-02** OIDC — not POC blockers.

| ID | Status | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|--------|-------|------|--------|------------|-------------|---------------------|
| ~~**W44-01**~~ | Complete | ABAC — resource labels and ownership | auth | L | W41-01, W38-01 | Done — `EnrichKVResourceLabels` middleware; list filtering in `secrets.go`; `abac_live_test.go`. | Policy `owner: team-a` denies read when secret metadata owner is `team-b`; list filtered when `list` + label condition. |
| ~~**W44-02**~~ | Complete | ABAC — environment and request attributes | auth | M | W13-01, W41-02 | Done — `X-KNX-Cluster`, `RequestPath` on `RequestContext`; environment tests in `policy_simulate_test.go` / `abac_live_test.go`. | Integration test: `environment: prod` policy denies when header/context says `staging`. |
| ~~**W44-03**~~ | Complete | Admin MFA enforcement via OIDC | auth | M | W37-02, W43-06 | Done — `require_mfa` on roles; `CheckMFA()` in `login_audit.go`; enforced in `LoginOIDC`. | Admin role without `mfa` claim → `403`; documented Keycloak/Azure AD mapper setup. |
| ~~**W44-04**~~ | Complete | Enterprise federation guide (SAML/LDAP → OIDC) | docs | S | W37-02 | Done — `docs/integration/enterprise-identity.md`. | `docs/integration/enterprise-identity.md` with architecture diagram and IdP config examples. |

> **Tier L sequencing:** **W44-01–02** (wire labels into auth context + integration tests) after **W41-01**. Native SAML → **LT-13**; full ABAC DSL → **LT-14**.

### Tier J — Advanced secret leasing

**Gap:** Dynamic engines (database, SSH) issue **per-engine** leases with renew/revoke, but there is no **unified lease API**, bulk revocation, role-level tuning beyond a single `ttl_seconds`, or cross-engine orchestration. `Lease` (`internal/domain/secrets/lease.go`) tracks `engine`, `role_name`, `renewable`, and expiry; cleanup is leader-only per engine (`internal/app/jobs.go`). Vault/OpenBao expose `sys/leases/*`, max TTL / period, lease quotas, and prefix revoke.

**Best-practice target:** operators can inspect and revoke leases without engine-specific URLs; roles enforce max TTL, renewability, and concurrency limits; rotation orchestration renews all dynamic engines; creds responses surface lease warnings before expiry.

| ID | Status | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|--------|-------|------|--------|------------|-------------|---------------------|
| ~~**W42-01**~~ | Complete | Unified lease lookup API | api | M | W12-02 | Done — `GET /sys/leases/:lease_id`, `internal/service/leases.go`, `handlers/leases.go`. | Lookup works for database and SSH leases; unknown id → `404`; audit `lease.lookup`. |
| ~~**W42-02**~~ | Complete | Lease list and filter API | api | M | W42-01 | Done — filters + pagination; CLI `sys leases list`; OpenAPI. | List returns consistent JSON across engines; integration test covers active vs revoked. |
| ~~**W42-03**~~ | Complete | Bulk lease revocation (by role or prefix) | api | M | W42-01 | Done — `PUT /sys/leases/revoke`, partial-result handling in `leases.go`. | Revoke-by-role clears all DB/SSH creds for role; audit per lease; idempotent on already-revoked. |
| ~~**W42-04**~~ | Complete | Role-level lease tuning (max TTL, renewability, period) | crypto | M | W12-01 | Done — `lease_tuning.go`, fields on DB/SSH roles; enforced in engines. | Role with `max_ttl=1h` rejects `ttl_seconds=24h`; `renewable=false` → renew returns `400`. |
| ~~**W42-05**~~ | Complete | Renew increment and lease warnings | api | S | W42-04 | Done — `lease_tuning_test.go` covers &lt;10% TTL `warnings[]` and renew cap. | Renew with increment > max extends only to cap; warning emitted when &lt;10% TTL remains. |
| ~~**W42-06**~~ | Complete | Multi-engine lease renewal in orchestration | crypto | M | W37-06 | Done — `ssh_grace` in rotation-run DTO; `runLeaseRenewal` leader job; `orchestration_ssh_test.go`, `jobs_ssh_renew_test.go`. | `rotation-run` reports `ssh_leases_renewed`; leader job renews SSH before expiry in integration test. |
| ~~**W42-07**~~ | Complete | Per-role lease quotas and issuance limits | storage | M | W42-04 | Done — `CheckMaxLeases` in `leaseutil.go`; metric `knxvault_leases_by_engine`. | Role with `max_leases=5` rejects 6th issuance; metric exposed on `/metrics`. |
| ~~**W42-08**~~ | Complete | Lease operator guide and runbooks | docs | S | W42-01–W42-03 | Done — `lease-management.md`, `day2.md` cross-links, SSH/DB renewal in leader jobs documented. | Runbook covers incident revoke-by-role; API reference lists `/sys/leases/*`. |

> **Tier J sequencing:** **W42-05–06** polish (warning tests, leader SSH renew). **W42-08** doc cross-links.

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
| ~~**W38-15**~~ | §7.4 | ~~API TLS bootstrap from vault PKI~~ | crypto | M | W37-01, W5-01 | Done — `POST /sys/tls/issue-listener` in `internal/api/handlers/sys.go`; CLI `sys issue-listener-tls`; K8s bootstrap in `docs/operations/pki-administration.md`. | Listener cert auto-renews before expiry; documented bootstrap for K8s. |
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
| ~~**W36-09**~~ | ~~Align leader status with live Raft role~~ | k8s | S | W26-02 | Done — `LeaderElector.IsLeader()` uses live Dragonboat probe; `internal/raft/leader_test.go`. | After forced leader step-down, `/health` `leader` and Prometheus gauge agree within one heartbeat RTT. |
| ~~**W36-10**~~ | ~~Dragonboat repository adapter tests~~ | ci | M | W26-01 | Done — `internal/repository/dragonboat/repo_test.go` with mock Raft client (CA, secret, lease, audit, PKI repos). | `go test ./internal/repository/dragonboat/...` passes; covers save/get/list for CA and secret repos. |
| ~~**W36-11**~~ | ~~Raft leader failover integration test~~ | ci | M | W28-01 | Done — `TestRaftLeaderFailover` in `test/integration/raft_test.go` (30s window). | Failover test in `make test-integration`. |
| ~~**W36-12**~~ | ~~HTTP API integration tests with Raft enabled~~ | ci | M | W26-01, W36-11 | Done — `api_raft_test.go`: KV, backup, PKI, `/ready` with Raft deps. | PKI + KV round-trip with `RAFT_ENABLED=true`. |

### Tier C — Auth, tokens & RBAC polish

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W36-13**~~ | ~~Persist client tokens in Raft~~ | auth | L | W25-02, W36-02 | Done — `token.save/get/revoke/list` Raft commands; `TokenRepository` + `TokenStore.SetRepository`; wired in `deps.go`. TTL cleanup job deferred. | `TestTokenStoreReplicated` + memory/dragonboat repos. |
| ~~**W36-14**~~ | ~~Wire `namespace` RBAC condition~~ | auth | S | W13-01 | Done — `RequestContext.Namespace` from `X-KNX-Namespace` header or K8s SA subject in `internal/api/middleware/auth.go`. | Policy with `namespace: prod` denies request without header; allows with `X-KNX-Namespace: prod`. |
| ~~**W36-15**~~ | ~~Fix `knxvault_active_leases` metric semantics~~ | docs | S | W15-02 | Done — `LeaseRepository.CountActive`, `updateActiveLeasesMetric` in `internal/app/jobs.go`; documented in `docs/metrics.md`; Grafana panel in `deployments/grafana/knxvault-overview.json`. | Metric reflects active leases; increments on creds generate, decrements on expire/revoke. |
| ~~**W36-16**~~ | ~~Leader election loop health & job gating~~ | k8s | S | W26-02 | Done — `knxvault_leader_election_running` metric, `leader.Monitor`, `/ready` 503 when election loop stops; jobs gated on leadership. | Kill leader election goroutine in test → `/ready` not ready; jobs do not run on follower. |

### Tier D — Features documented but missing

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W36-17**~~ | ~~Master key rotation API~~ | crypto | L | W3-02, W36-04 | Done — `internal/crypto/keyring.go`, `POST /sys/rotate-master-key`, re-encrypt job, CLI `sys rotate-master-key`, `docs/product/tier-b-production.md`. | Rotate + transition + CLI. |
| ~~**W36-18**~~ | ~~Managed database credentials execution mode~~ | crypto | L | W12-01 | Done — `execution_mode: managed`, KV `connection_url`, SQLite executor + unit test; `docs/deploy/database-credentials.md`. | Managed role executes creation/revocation SQL. |
| ~~**W36-19**~~ | ~~Return revocation SQL on lease revoke (client mode)~~ | api | S | W12-01 | Done — `RevokeResult` in DB engine; handler returns `200` + `revocation_statements` or `204` (`handlers/database.go`). | `PUT /secrets/database/revoke/:id` returns SQL strings when role defines them. |
| ~~**W36-20**~~ | ~~Wire `EngineRegistry` at startup~~ | api | S | W6-01 | Done — KV + database engines registered in `internal/app/deps.go`; `TestNewDependenciesEngineRegistry` in `deps_test.go`. | Registry lists 2 engines; no behavior change for existing API. |
| ~~**W36-21**~~ | ~~CLI parity for Day-2 operations~~ | docs | M | W20-01 | Done — `sys roles list/delete`, `sys raft-add-node`/`raft-remove-node`, `pki revoke`/`renew`; API `GET/DELETE /sys/roles`. | Each documented CLI command in LLD §11 has working cobra subcommand. |
| ~~**W36-22**~~ | ~~LLD / security-model doc reconciliation~~ | docs | S | W36-01, W36-02, W36-04 | Done — `docs/lld.md` §7 status tags, `docs/architecture/security-model.md` agent/CSI auth, `docs/product/lld-alignment.md`. | No doc claims production feature that code lacks without "planned" tag. |

### Tier E — Deferred alongside Phase 5

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| ~~**W36-23**~~ | ~~Dynamic Raft cluster membership~~ | storage | XL | W28-02 | Done — `Client.AddNode`/`RemoveNode`, `POST /sys/raft/*`, `docs/operations/runbooks/scaling.md`. | API + runbook for expand/shrink. |
| ~~**W36-24**~~ | ~~Vault seal / unseal operational mode~~ | security | L | W36-17 | Done — `SealState`, `SealGuard` middleware, `POST /sys/seal`/`unseal`, CLI, `KNXVAULT_UNSEAL_KEY`. | Seal blocks writes; unseal restores. |

> **Phase 5 dependency note:** **W37-01** supersedes **W34-01** (mTLS) in priority. **W32-**\* (multi-tenancy) should follow **W41-01** / **W36-14**. **W36-13** (token persistence) should precede **W34-02** (client cert issuance).

---

## Phase 5 — Ecosystem (planned)

High-level scope from LLD §9.4. Phase 3 is complete; Phase 4 hardening recommended first. Detailed design in [`docs/design/phase4-ecosystem.md`](design/phase4-ecosystem.md).

| ID | Status | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|--------|-------|------|--------|------------|-------------|---------------------|
| **W30-01** | Partial | Kubernetes Operator scaffold | k8s | L | W29 | `cmd/operator/main.go`, CRD manifest `deployments/operator/crd-knxvault-ca.yaml`. **Gap:** no kubebuilder/controller-runtime project or Go CRD types. | CRDs apply cleanly; scaffold compiles. |
| **W30-02** | Not started | Operator reconciliation loop | k8s | L | W30-01 | `internal/operator/operator.go` is a stub (sleep + print; no controller-runtime). | Create CA via CRD → visible in API; e2e test passes. |
| ~~**W31-01**~~ | Complete | OpenSSL engine abstraction | crypto | M | W3-03 | Done — `Engine` interface + `CLIEngine` in `internal/crypto/openssl/engine.go`; mock tests. | Unit tests with mock engine. |
| **W31-02** | Not started | PKCS#11 HSM integration | crypto | L | W31-01 | Stub only — `pkcs11_stub.go`; `deps.go` supports `native`/`openssl` only. | Root CA created on SoftHSM; documented config. |
| **W32-01** | Partial | Multi-tenancy policy model | auth | M | W41-01, W36-14 | Namespace condition + `ResolveTenantNamespace` (SA spoofing blocked). **Gap:** no automatic namespace-scoped policy isolation beyond evaluator. | Cross-tenant access denied in tests. |
| ~~**W32-02**~~ | Complete | Tenant-aware API enforcement | api | M | W32-01 | Done — `TenantEnforcement` middleware; `KNXVAULT_TENANT_MODE`; `test/integration/tenant_test.go`. | Integration tests for tenant boundaries. |
| **W32-03** | Partial | Tenant-scoped repository isolation | storage | L | W32-01 | `tenantrepo.WrapSecret` exists (`internal/repository/tenant/secret.go`). **Gap:** not wired in `deps.go`; isolation is service-layer path scoping. | Cross-tenant `Get` returns `404` even if policy misconfigured; Raft ops carry tenant key. |
| **W32-04** | Partial | Tenant isolation across services and engines | api | L | W32-03 | KV tenant scoping in `SecretsService` + rotation paths. **Gap:** DB, SSH, PKI, inject, CSI not fully tenant-scoped. | Integration test: tenant A token cannot read tenant B KV path via any API surface. |
| **W32-05** | Partial | Multi-tenant isolation test matrix | ci | M | W32-04 | `test/integration/tenant_test.go` (3 KV cases). **Gap:** no matrix for policy deny, CSI, backup export, or CSV artifact. | `make test-integration` tenant suite; CSV report for compliance packs (**W35-02**). |
| **W33-01** | Partial | Valkey read cache | storage | M | W26 | Done for KV — `internal/cache/valkey.go`, `KNXVAULT_VALKEY_CACHE_URL`, wired in `deps.go`. **Gap:** CA, CRL, policies not cached; no cache-hit metrics. | Cache hit metrics; fallback on miss. |
| **W33-02** | Partial | Cache invalidation on write | storage | S | W33-01 | KV `invalidateCache` on write/destroy (`secrets.go`). **Gap:** not Raft-commit-wide across all cached resource types. | Write → read sees fresh data. |
| **W34-01** | Partial | Server mTLS | security | M | W5-03 | Server TLS + `MTLSRequired` on KV writes (`tlsconfig.go`, `mtls.go`). **Gap:** not enforced on all secured/admin routes (superseded in part by **W37-01**). | mTLS handshake test; opt-in flag. |
| **W34-02** | Partial | Client cert issuance API | security | M | W34-01 | Done — `POST /pki/issue-client-cert`. **Gap:** no cert-based authentication method for API consumers. | Issue + authenticate with client cert. |
| **W35-01** | Partial | DR automation | ops | L | W27 | `scripts/dr-failover.sh` (restore via `/sys/restore`). **Gap:** no cross-cluster backup replication. | DR drill documented and tested. |
| **W35-02** | Partial | Compliance audit packs | docs | M | W14 | Done — `GET /sys/audit/pack`, `auditpack.go`, CLI. **Gap:** audit export + manifest only; no SOC2/PCI/ISO control-mapping bundles. | Pack generation CLI command. |

---

## Long-term future

Deferred packaging and ecosystem work — not scheduled for Tier 0 / Phase 4–5 near-term delivery. Revisit after **W37** checklist items and **W36** hardening stabilize.

| Item | Area | Rationale |
|------|------|-----------|
| **Helm chart** | k8s | Deferred as **LT-03**. Near-term: raw manifests in `deployments/k8s/` (**W28-02**). |
| **Cloud dynamic secrets (AWS IAM)** | crypto | Deferred as **LT-02**. Near-term: database dynamic engine + OIDC auth. |
| Helm hooks (pre-upgrade backup) | k8s | Depends on **LT-03** Helm chart. |
| Grafana dashboards bundled in chart | docs | Depends on **LT-03** Helm chart + W10 metrics. |
| gRPC API, Web UI, OPA integration | api | **LT-04–LT-06** (LLD §10.3). |
| FIPS OpenSSL, Falco rules | security | **LT-07–LT-08** (LLD §7.6–7.7). |
| MkDocs / GitHub Pages publishing | docs | **LT-11** (LLD §12.1). |
| Performance benchmarking suite | ci | **LT-12** (LLD §9.5). |

### Long-term backlog (detailed)

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| **LT-01** | Terraform provider | docs | L | LT-03, Phase 5 stable | **Gap:** LLD §9.4 / §12.2.4 Terraform provider; no IaC. **Hint:** `terraform-provider-knxvault/` with `hashicorp/terraform-plugin-framework`. Resources: `knxvault_kv_secret`, `knxvault_policy`, `knxvault_pki_root` (data). Auth via `KNXVAULT_TOKEN`. `docs/integration/terraform.md`. Defer until **LT-03** (Helm), **W36-02** (TokenReview), and API surface stable (**W38-01**). | `terraform apply` creates KV + policy; destroy removes. CI acceptance test. |
| **LT-02** | Cloud dynamic secrets engine (AWS IAM scaffold) | crypto | XL | W37-02, W36-20 | **Gap:** LLD §9.4 “Advanced dynamic secret engines (AWS, cloud OAuth)”; only DB engine exists. **Hint:** `internal/engine/secrets/aws/` + `POST /secrets/aws/creds/:role`; STS `AssumeRole` via **W37-02** OIDC. Register in **W36-20** `EngineRegistry`. **No near-term impact on vanilla K8s/KubeVirt** — use KV + database engine instead. | Temporary IAM creds issued; lease documented; LocalStack or sandbox test. |
| **LT-03** | Helm chart (production install) | k8s | M | W28-02, W37-01 | **Gap:** LLD §1.2, §6.1, §6.6 Helm-first deployment; only `deployments/helm/.gitkeep` + raw manifests. **Hint:** `deployments/helm/knxvault/` per LLD §6.1: `values.yaml` (`raft.*`, `persistence`, `tls`), StatefulSet from `statefulset.yaml`, Service/Ingress templates. Hooks → **LT-09**. Defer until **W37-01** TLS and **W38-05** PDB/NetPol patterns proven in raw manifests. | `helm install` 3-node Raft; README + `docs/deploy/kubernetes.md` updated. |
| **LT-04** | gRPC API alongside REST | api | L | Phase 5 stable | **Gap:** LLD §10.3 gRPC for service mesh. **Hint:** `api/proto/knxvault/v1/` with grpc-gateway or parallel handlers; mTLS from **W37-01**. | grpcurl list/get KV works; REST unchanged. |
| **LT-05** | Web UI admin console | docs | XL | Phase 5 stable | **Gap:** LLD §10.3 optional React/Vue UI. **Hint:** Separate repo `knxvault-ui/` consuming OpenAPI; OIDC login (**W37-02**). | Read-only secrets/PKI view; no secrets in browser storage. |
| **LT-06** | OPA / Gatekeeper policy integration | auth | L | W41-04, W32-01 | **Gap:** LLD §10.3 “Policy as Code” with OPA. **Hint:** Export KNXVault policies to Rego bundle; optional `POST /sys/policy/validate` delegating to OPA sidecar (after **W41-04** simulation baseline). | Deny rule in OPA blocks matching KNXVault policy eval. |
| **LT-07** | OpenSSL FIPS mode | security | M | W31-01 | **Gap:** LLD §7.6 FIPS via OpenSSL config. **Hint:** `KNXVAULT_OPENSSL_FIPS=true` sets `OPENSSL_FIPS` or FIPS config path in `internal/crypto/openssl/wrapper.go`; document compliance limits. | FIPS-enabled image issues cert in test harness. |
| **LT-08** | Falco rules for OpenSSL anomalies | security | S | W10-01 | **Gap:** LLD §7.7 Falco rules. **Hint:** `deployments/falco/knxvault-rules.yaml` detecting unexpected `openssl` exec paths outside wrapper temp dirs. | Falco alerts in test when exec escapes pattern. |
| **LT-09** | Helm pre-upgrade backup hooks | k8s | S | LT-03, W27-01 | **Gap:** LLD §6.6 upgrade safety. **Hint:** Helm `pre-upgrade` Job calling `POST /sys/backup` with RBAC token from Secret. | `helm upgrade` creates backup Secret before rollout. |
| **LT-10** | Multi-region CA federation | crypto | XL | W35-01 | **Gap:** LLD §10.3 multi-region hierarchy. **Hint:** Cross-cluster CA trust bundle replication via encrypted backup sync; design doc only initially. | Design doc + PoC two-cluster trust. |
| **LT-11** | MkDocs / GitHub Pages documentation site | docs | M | W38-19 | **Gap:** LLD §12.1 version-controlled docs published via MkDocs or GitHub Pages; repo is Markdown-only with no site build. **Hint:** `mkdocs.yml` + Material theme; CI deploy to GitHub Pages on release tag; OpenAPI + CLI refs linked. Defer until **W38-19** traceability matrix stabilizes. | `mkdocs serve` renders `/docs/`; release tag publishes public site. |
| **LT-12** | Performance benchmarking suite | ci | M | W29-02 | **Gap:** LLD §9.5 “performance benchmarking” cross-cutting activity; no `bench/` or SLO targets. **Hint:** `test/bench/` with `testing.B` for KV put/get, Raft propose, OpenSSL issue; optional `ghz` for HTTP; record baselines in `docs/engineering/performance.md`. Not blocking HA correctness. | CI stores bench results; regression &gt;20% fails advisory gate. |
| **LT-13** | Native SAML authentication method | auth | XL | W37-02, W43-06 | **Gap:** Prospect P2 identity federation; today OIDC+K8s only. **Hint:** SAML SP or broker integration in `internal/auth/saml.go`; prefer **W44-04** (IdP broker via OIDC) for near-term. | SAML assertion login mints client token; metadata endpoint documented. |
| **LT-14** | Declarative ABAC policy language (DSL) | auth | XL | W44-01, W41-10, LT-06 | **Gap:** Prospect declarative policy evolution beyond JSON+HCL subset. **Hint:** CEL or Rego bundle authoring; policy modules with versioned schema. After **W41-10** composition and **LT-06** OPA baseline. | Policy DSL compiles to internal JSON; simulation API (**W41-04**) validates DSL policies. |