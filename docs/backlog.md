<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# KNXVault Backlog

Actionable backlog derived from [`docs/lld.md`](lld.md). Items are **topologically sorted by dependency** — implement in listed order within each phase.

**Current focus (2026-07-16):** **P0 W50 audit remediation** (full-codebase review 7f32c606) after W30 Complete + **operator hardening P0/P1/P2** (SA auth, leader election, CSR sign API, issuer vault Ready, Secret annotations, delivery None, backoff, ns RBAC example). Prefer KNXVault PKI + operator for vault-issued TLS (**no cert-manager**). Remaining Phase 5: tenant depth (W32), HSM (W31-02).

**Milestone M-ACME-1 (P1):** Unified **Let's Encrypt / ACME** for **standalone + Kubernetes + `knxvault-cli acme`** — design [`docs/design/acme-letsencrypt-unified.md`](design/acme-letsencrypt-unified.md), backlog **W60-01…** below. K8s operator ACME already shipped; gap is CLI + standalone.

**Milestone M-DNS01-1 (P1, after M-ACME-1):** cert-manager-class **DNS-01 providers + webhooks** — design [`docs/design/dns01-providers-and-webhooks.md`](design/dns01-providers-and-webhooks.md), backlog **W61-01…** below. Webhook-first extensibility; optional in-tree Route53/RFC2136.

**Milestone M-PRODSEC-1 (P0/P1):** Production **set-and-forget** security profile, bootstrap root death, production kustomize, doctor gate — design [`docs/design/production-security-posture.md`](design/production-security-posture.md), assessment [`docs/architecture/security-posture-assessment.md`](architecture/security-posture-assessment.md), backlog **W62-01…** below.

**Milestone M-CUSTODY-1 (P1, after M-PRODSEC-1 core):** KMS auto-unseal + master wrap / optional PKCS#11 — same design doc §6 / §8 Phase 1, backlog **W63-01…**. Optional multi-tenant SaaS isolation **W64-*** only if product goal.

**Vault-class capability program (P0/P1):** **Partial shipped** (leases/wrap/transit/identity/LDAP/sync-docs) — master plan [`docs/design/vault-class-capability-plan.md`](design/vault-class-capability-plan.md) — leases **W67**, wrapping/cubbyhole **W66**, transit **W65**, JWT **W71**, identity **W68**, dyn engines **W69**, DR **W72**, sync **W73**. Cloud IAM (**LT-02**) and cloud auth (**LT-15**) **not near-term**. No plugin framework.

**W74 security audit remediation (2026-07-17):** LDAP lock-down, wrap/identity persistence, lease cascade/bulk safety, transit race+AAD, webhook SafeHTTPClient — [security-remediation-w74-2026-07-17.md](audit/security-remediation-w74-2026-07-17.md).

**W78 full audit pack (2026-07-17):** CSR email/URI, LDAP max TTL, ACME SSRF+skipTLS, PKI default role, SQL strict, operator Secrets RBAC, unseal CIDRs, OIDC/JWKS, audit forward, KeyUsage, CSI fileName, ImportCA match, AppRole salt, unseal CT — [security-remediation-w78-2026-07-17.md](audit/security-remediation-w78-2026-07-17.md).

**W79 residual pack (2026-07-17):** SafeHTTP no proxy; operator Secret read scoped; PKI ACL split; SQL SUPERUSER deny; OIDC audience+https JWKS; CGNAT SSRF; unseal /0 reject; AppRole salted-only — [security-remediation-w79-2026-07-17.md](audit/security-remediation-w79-2026-07-17.md).

**W75 CIS hardening (network + defaults + multi-tenant stance):** design [`docs/design/cis-hardening-improvements.md`](design/cis-hardening-improvements.md). **P0 done:** multi-node Raft forces production profile (**W75-01**); `deployments/k8s/production/` (**W75-02**).

**Post-quantum readiness** is tracked separately: **[`docs/pq/backlog.md`](pq/backlog.md)** (`PQ-*` IDs) with design under [`docs/pq/`](pq/README.md). Not a claim of PQ-ready product.

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
| Complete (P0 operator / cert-manager replacement) | 10 | **W30-01–W30-10** |
| Partial | 10 | W32-01, W32-03–05, W33-01–02, W34-01–02, W35-01–02 |
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
| ~~**W1-02**~~ | ~~Production Makefile (fmt, vet, lint, test, build, sbom, scan)~~ | ci | S | W1-01 | Root `Makefile` providing the standard Go developer/CI workflow referenced in LLD §3.1 and §9.5 (SBOM generation). | Done — `make all` passes; `make` defaults to `help`; static `build/bin/knxvault`; CycloneDX `sbom.json` + `sbom-binary.json`; Trivy scan clean (`.trivyignore` for unused transitive paths); `GOTOOLCHAIN=go1.25.11`; golangci-lint v2. |
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
| ~~**W9-01**~~ | ~~Container image (Dockerfile)~~ | k8s | S | W1-02 | Multi-stage Dockerfile producing a minimal non-root image. | Done — `Dockerfile`, `.dockerignore`, `make container-build`, `-healthcheck` flag. |
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
| ~~**W38-25**~~ | §7.7, §9.5 | ~~Distroless/hardened production container image~~ | ci | M | W1-02 | Done — multi-stage → `gcr.io/distroless/static-debian13:nonroot`; OpenSSL CLI PKI backend **removed**; native Go only. | No openssl binary or backend in product. |

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

High-level scope from LLD §9.4. Phase 3–4 core is largely complete. Detailed design: [`docs/design/phase4-ecosystem.md`](design/phase4-ecosystem.md).

### P0 — Native CRD automation (replace cert-manager)

**Product goal:** For **any TLS issued by KNXVault PKI**, clusters do **not** need cert-manager. KNXVault remains the CA; a first-class **operator** owns Kubernetes desired-state (CRDs → issue/renew → `kubernetes.io/tls` Secret). cert-manager’s Vault issuer shim (**W40-02**) becomes **optional legacy** for environments that already run cert-manager; ACME/public CAs remain out of scope (LT / external tooling).

**Principle:** Vault pods do **not** write Kubernetes Secrets. The **operator** is the only K8s citizen; it authenticates with ServiceAccount JWT → `POST /auth/kubernetes` (same pattern as CSI/ESO).

**Implement in order:** W30-01 → W30-02 → W30-03 → W30-04 → W30-07 (minimum viable “no cert-manager”), then W30-05/06/08/09, then W30-10.

| ID | Priority | Status | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|----------|--------|-------|------|--------|------------|-------------|---------------------|
| ~~**W30-01**~~ | — | Complete | Operator controller-runtime scaffold | k8s | L | W29 | Done — `cmd/operator`, `internal/operator` + controller-runtime manager, `make build-operator`, CRDs under `deployments/operator/crds/`. | Binary builds; manager starts. |
| ~~**W30-02**~~ | — | Complete | Reconcile `KNXVaultCA` → PKI API | k8s | L | W30-01 | Done — `CAReconciler` root/intermediate via `vaultiface`; status Ready/caId/serial. | Unit test + lab e2e. |
| ~~**W30-03**~~ | — | Complete | `KNXVaultCertificate` + TLS Secret | k8s | L | W30-02 | Done — `CertificateReconciler` issues + materialises `kubernetes.io/tls` Secret. | Secret created for sample Certificate CR. |
| ~~**W30-04**~~ | — | Complete | Renew lifecycle, status, metrics | k8s | M | W30-03 | Done — `renew` package, requeue, revision, Prometheus counters. | Unit tests for schedule; metrics registered. |
| ~~**W30-05**~~ | — | Complete | Issuer / ClusterIssuer multi-ns | k8s | M | W30-03 | Done — `KNXVaultIssuer` + `KNXVaultClusterIssuer` reconcilers + `ResolveVaultRole`. | Cross-ns issue via ClusterIssuer. |
| ~~**W30-06**~~ | — | Complete | Ingress annotation shim | k8s | M | W30-05 | Done — `IngressReconciler` + `knxvault.kubenexis.dev/issuer`; gate `KNXVAULT_OPERATOR_INGRESS_SHIM`. | Annotation creates Certificate CR. |
| ~~**W30-07**~~ | — | Complete | Operator e2e without cert-manager | ci | M | W30-04 | Done — `scripts/lab-operator-e2e.sh`, `scripts/test-operator-kind.sh`. | Lab e2e PASS on kube node. |
| ~~**W30-08**~~ | — | Complete | Docs: operator-first PKI | docs | S | W30-03 | Done — `pki-replace-cert-manager.md`, updated pki-kubernetes + kubernetes-native. | Operator-first onboarding. |
| ~~**W30-09**~~ | — | Complete | cert-manager migration guide | docs | M | W30-05 | Done — `deployments/operator/migration/`. | Mapping table + sample YAML. |
| ~~**W30-10**~~ | — | Complete | `KNXVaultCertificateRequest` | k8s | M | W30-03 | Done — CSR parse + issue fallback; optional Secret. | Controller + tests. |

> **P0 non-goals:** ACME / Let’s Encrypt / DNS-01 (remain external or LT). Do not vendor cert-manager. Do not teach Raft pods to call the Kubernetes apiserver for Secrets.

> **P0 sequencing note:** W40-02 (cert-manager Vault shim) stays **Complete** for compatibility but is **not** the preferred integration once W30-03+ ship.

### Other Phase 5 items

| ID | Priority | Status | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|----------|--------|-------|------|--------|------------|-------------|---------------------|
| ~~**W31-01**~~ | — | Complete | OpenSSL engine abstraction | crypto | M | W3-03 | Done — `Engine` interface + `CLIEngine` in `internal/crypto/openssl/engine.go`; mock tests. | Unit tests with mock engine. |
| **W31-02** | P1 | Not started | PKCS#11 HSM integration | crypto | L | W31-01 | Stub only — `pkcs11_stub.go`; `deps.go` supports `native`/`openssl` only. Complements operator CA CRs with HSM-backed roots. | Root CA created on SoftHSM; documented config. |
| **W32-01** | P1 | Partial | Multi-tenancy policy model | auth | M | W41-01, W36-14 | Namespace condition + `ResolveTenantNamespace` (SA spoofing blocked). **Gap:** no automatic namespace-scoped policy isolation beyond evaluator. | Cross-tenant access denied in tests. |
| ~~**W32-02**~~ | — | Complete | Tenant-aware API enforcement | api | M | W32-01 | Done — `TenantEnforcement` middleware; `KNXVAULT_TENANT_MODE`; `test/integration/tenant_test.go`. | Integration tests for tenant boundaries. |
| **W32-03** | P1 | Partial | Tenant-scoped repository isolation | storage | L | W32-01 | `tenantrepo.WrapSecret` exists (`internal/repository/tenant/secret.go`). **Gap:** not wired in `deps.go`; isolation is service-layer path scoping. | Cross-tenant `Get` returns `404` even if policy misconfigured; Raft ops carry tenant key. |
| ~~**W32-04**~~ | P1 | Complete | Tenant isolation across services and engines | api | L | W32-03 | Done (W53) — KV + DB/SSH/PKI `SetTenantMode` + `scopeResourceName`. Inject uses tenant-scoped SecretsService. **Residual:** CSI path matrix / lease ID tenant prefix. | Unit + integration tenant suite. |
| **W32-05** | P1 | Partial | Multi-tenant isolation test matrix | ci | M | W32-04 | `test/integration/tenant_test.go` (3 KV cases). **Gap:** no matrix for policy deny, CSI, backup export, or CSV artifact. | `make test-integration` tenant suite; CSV report for compliance packs (**W35-02**). |
| **W33-01** | P2 | Partial | Valkey read cache | storage | M | W26 | Done for KV — `internal/cache/valkey.go`, `KNXVAULT_VALKEY_CACHE_URL`, wired in `deps.go`. **Gap:** CA, CRL, policies not cached; no cache-hit metrics. | Cache hit metrics; fallback on miss. |
| **W33-02** | P2 | Partial | Cache invalidation on write | storage | S | W33-01 | KV `invalidateCache` on write/destroy (`secrets.go`). **Gap:** not Raft-commit-wide across all cached resource types. | Write → read sees fresh data. |
| **W34-01** | P1 | Partial | Server mTLS | security | M | W5-03 | Server TLS + `MTLSRequired` on KV writes (`tlsconfig.go`, `mtls.go`). **Gap:** not enforced on all secured/admin routes (superseded in part by **W37-01**). | mTLS handshake test; opt-in flag. |
| ~~**W34-02**~~ | P1 | Complete | Client cert issuance + API login | security | M | W34-01 | Done — `POST /pki/issue-client-cert` + `POST /auth/cert` (mTLS CN/SAN → role policies, W53). **Residual:** dedicated trust store beyond TLS handshake. | Issue + authenticate with client cert. |
| **W35-01** | P2 | Partial | DR automation | ops | L | W27 | `scripts/dr-failover.sh` (restore via `/sys/restore`). **Gap:** no cross-cluster backup replication. | DR drill documented and tested. |
| **W35-02** | P2 | Partial | Compliance audit packs | docs | M | W14 | Done — `GET /sys/audit/pack`, `auditpack.go`, CLI. **Gap:** audit export + manifest only; no SOC2/PCI/ISO control-mapping bundles. | Pack generation CLI command. |

> **Phase 5 dependency note:** **P0 W30-*** is current focus (cert-manager avoidance). **W32-*** (multi-tenancy) should follow for multi-team issuers. **W31-02** (HSM) pairs with production CA CRs. **W36-13** (token persistence) should precede full **W34-02** (client cert API auth).

---


## P0/P1 — Full-codebase audit remediation (2026-07-16, review `7f32c606`)

Source: [`docs/audit/formal-10cycle-full-codebase-2026-07-16.md`](audit/formal-10cycle-full-codebase-2026-07-16.md), multi-pass reviews, multi-issuer review `f29a75bd`.

**Product goal:** Close Critical/High findings so multi-tenant deploy, ESO, webhook, ACME, and HA auth are production-safe.

| ID | Priority | Status | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|----------|--------|-------|------|--------|------------|-------------|---------------------|
| ~~**W50-01**~~ | P0 | Complete | ESO fetch requires inbound auth | security | S | W40-01 | Done — SA auto-login opt-in only. | Anonymous fetch → 401. |
| ~~**W50-02**~~ | P0 | Complete | Webhook serves TLS only | k8s | M | W38-07 | Done — TLS cert/key required (plaintext opt-in for tests). | ListenAndServeTLS. |
| ~~**W50-03**~~ | P0 | Complete | Seal blocks secret reads + start-sealed | security | M | W37 | Done — SealGuard all methods; start sealed when key set; seal.state file. | Sealed GET denied. |
| ~~**W50-04**~~ | P0 | Complete | AppRole durable store | auth | M | W40-02 | Done — file persist under raft data dir (not full Raft multi-node yet). | Reload on restart. |
| ~~**W50-05**~~ | P0 | Complete | Init state durable | api | S | W8 | Done — init.state under raft data dir. | Survives process restart. |
| ~~**W50-06**~~ | P0 | Complete | Server SA TokenReview RBAC | k8s | S | W36-01 | Done — `clusterrole-tokenreview.yaml`. | TokenReview create. |
| ~~**W50-07**~~ | P0 | Complete | ACME SSRF + AcceptTOS + HTTP-01 wire | security | L | multi-issuer | Done — URL private deny; acceptTOS; shared HTTP-01 listener. | Unit tests. |
| ~~**W50-08**~~ | P0 | Complete | OpenSSL CN DN injection | crypto | S | W3-03 | Done — ValidateCommonName. | Rejects `/`. |
| ~~**W50-09**~~ | P0 | Complete | Operator Gateway RBAC + secrets docs | k8s | S | W30 | Done — gateway rules; namespaced secrets preferred in docs. | RBAC yaml. |
| ~~**W50-10**~~ | P0 | Complete | Prod rate limit on + HTTP timeouts | security | S | W10 | Done — ConfigMap true; server timeouts. | Manifests. |
| ~~**W50-11**~~ | P1 | Complete | Auth middleware fail-closed | auth | S | W7-05 | Done — nil svc aborts. | Unit path. |
| ~~**W50-12**~~ | P1 | Complete | Agent delegate max TTL | auth | S | W7 | Done — cap 1h. | Server-side clamp. |
| ~~**W50-13**~~ | P1 | Complete | ACME account key Secret load/store | security | M | W50-07 | Done — load/store PrivateKeySecretRef PEM; generate if missing. | Persist LE account key. |
| ~~**W50-14**~~ | P1 | Complete | ResolveVaultRole structured vault | k8s | M | W30-10 | Done — ResolveIssuerSpec for vaultCAName/vault{}. | Structured vault mode. |
| ~~**W50-15**~~ | P1 | Complete | IP SANs self-signed | crypto | S | W50-07 | Done — parseIPs on OrderRequest. | IP SANs present. |
| ~~**W50-16**~~ | P1 | Complete | DEK memzero on Seal/Open hot path | crypto | S | W3-02 | Done — memzero.Bytes on DEK after Seal/Open. | Zero DEK after use. |
| ~~**W50-17**~~ | P1 | Complete | SyncRBAC fail-closed option | auth | M | W41 | Done — `KNXVAULT_RBAC_SYNC_FAIL_CLOSED` (default true). | Config fail-closed. |
| ~~**W50-18**~~ | P1 | Complete | Lockout cluster-aware / trusted proxies | auth | M | W43-04 | Done — SetTrustedProxies; identity-preferring lockout keys. | Document + identity key. |
| ~~**W50-19**~~ | P2 | Complete | Metrics auth / separate bind | security | S | W10 | Done — MetricsBearerToken + NetworkPolicy scrape notes. | Optional auth. |
| ~~**W50-20**~~ | P2 | Complete | Raft mTLS required in production profile | security | M | W38-14 | Done — multi-node Raft requires mTLS unless ALLOW_INSECURE. | ValidateSecurity. |
| ~~**W50-21**~~ | P2 | Complete | Rate limiter bucket eviction | api | S | W10 | Done — max 10k buckets + idle TTL eviction. | Bounded map. |
| ~~**W50-22**~~ | P2 | Complete | Managed DB SQL allow-list mode | security | M | W37 | Done — ValidateManagedSQLStatements on managed roles. | Strict template-only. |
| ~~**W50-23**~~ | P2 | Complete | CSI socket permissions | k8s | S | W39 | Done — socket dir 0700, socket 0660. | Hardened perms. |
| ~~**W50-24**~~ | P2 | Complete | Exposure HMAC timestamp/nonce | security | S | W37 | Done — timestamp header + 5m skew in HMAC. | Signed timestamp. |
| ~~**W50-25**~~ | P2 | Complete | OpenAPI full route parity | api | M | W8-03 | Done — vault-compat + auth/sys paths added (best-effort). | Spec closer to router. |
| ~~**W50-26**~~ | P2 | Complete | Root token short TTL / rotation recipe | auth | S | W7 | Done — default 72h root TTL + docs. | Shorter default. |
| ~~**W50-27**~~ | P2 | Complete | Audit forwarder queue/metrics | ops | M | W14 | Done — bounded queue + sent/dropped/failed metrics. | Bounded queue. |
| ~~**W50-28**~~ | P2 | Complete | Unseal multi-share / lockout | security | L | W37 | Done — progressive backoff + Shamir multi-share (`KNXVAULT_UNSEAL_THRESHOLD`, share submit, generate-unseal-shares, W53). | Progressive delay + t-of-n unseal. |
| ~~**W50-29**~~ | P2 | Complete | Vaultcompat path-scoped pki capability | auth | M | W41 | Done — RequirePKISignCapability with pki write fallback. | Path capability. |
| ~~**W50-30**~~ | P2 | Complete | ACME account key + sealed-read tests | ci | M | W50-07, W50-03 | Done — unit tests for account key + seal guard reads; Pebble e2e remains optional lab. | Tests green. |

---


### W51 — 5-cycle security auditor (2026-07-16)

| ID | Sev | Status | Title |
|----|-----|--------|-------|
| ~~W51-01~~ | High | Complete | SignCSR enforces role AllowedDomains/MaxTTL |
| ~~W51-02~~ | High | Complete | RequireKVAccess fail-closed |
| ~~W51-03~~ | High | Complete | ClientCertFingerprint SHA-256 |
| ~~W51-04~~ | Medium | Complete | ACME ValidateDirectoryURL + ESO path + agent .. + audit redact |
| W51-05 | Medium | Open | SignCSR IP SAN role constraints (residual) |

Report: `docs/audit/formal-5cycle-security-auditor-2026-07-16.md`.


### W52 — Full security audit remediation (2026-07-16)

| ID | Sev | Status | Title |
|----|-----|--------|-------|
| ~~W52-01~~ | Critical | Complete | seal.state never auto-unseals |
| ~~W52-02~~ | High | Complete | PKI allowed_domains required / default-deny |
| ~~W52-03~~ | High | Complete | SignCSR/Issue require PKI role (default * role per CA) |
| ~~W52-04~~ | High | Complete | Path-scoped PKI sign (no coarse pki write fallback) |
| ~~W52-05~~ | High | Complete | RateLimitEnabled default true |
| ~~W52-06~~ | High | Complete | HTTPS required for CSI/SDK non-loopback |
| ~~W51-05~~ | Medium | Complete | IP SANs require allowed_domains * |
| ~~W52-R~~ | — | Complete (W53) | Multi-tenant non-KV, Shamir unseal, AppRole Raft, client-cert login, shared rate/lockout — see W53 |

Report: `docs/audit/formal-security-remediation-w52-2026-07-16.md`.


### W53 — Residual security features (2026-07-16)

| ID | Status | Title |
|----|--------|-------|
| ~~W53-01~~ | Complete | Multi-tenant isolation for DB/SSH/PKI (`tenantMode` + scope) |
| ~~W53-02~~ | Complete | Shamir multi-share unseal (`internal/crypto/shamir`, SubmitShare) |
| ~~W53-03~~ | Complete | AppRole Raft replication (`sys/internal/approles` encrypted blob) |
| ~~W53-04~~ | Complete | Client-cert API login (`POST /auth/cert`) |
| ~~W53-05~~ | Complete | Cluster-shared rate-limit / lockout (Valkey `cache.Store`) |

Report: `docs/audit/formal-w53-residual-features-2026-07-16.md`.

**Still residual (product):** HSM PKCS#11 (**W31-02**), tenant-scoped CSI/lease matrix, atomic INCR for shared counters, AppRole follower push-notify.

## Milestone M-ACME-1 — Unified ACME / Let's Encrypt (standalone + K8s + CLI)

**Status:** Complete (M-ACME-1 A-C + D stubs 2026-07-17).  
**Design:** [`docs/design/acme-letsencrypt-unified.md`](design/acme-letsencrypt-unified.md)  
**Depends on:** Existing `internal/acme` + operator multi-issuer ACME ([multi-issuer-acme.md](design/multi-issuer-acme.md), W30 complete).  
**Priority:** **P1** (product completeness for public TLS on standalone + CLI parity).

| Field | Value |
|-------|-------|
| **Claim when done** | LE/ACME automation for **Kubernetes and standalone** via shared engine + **`knxvault-cli acme`**; private CA stays `pki` |
| **Phases** | **A** foundation · **B** standalone productization · **C** K8s alignment · **D** optional vault ACME state (**M-ACME-2** stretch) |
| **Exit** | Acceptance criteria in design §7 |

### Phase A — Shared engine + CLI MVP

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W60-01** | P1 | Complete | M | crypto | — | File account key store | `AccountKeyProvider` for PEM path (`0600`); load/create ECDSA account key | Unit tests; no key material in logs |
| **W60-02** | P1 | Complete | M | crypto | W60-01 | File cert state store | Persist domain, notAfter, paths, directory URL for renew decisions | Atomic write; corrupt file fails closed |
| **W60-03** | P1 | Complete | M | crypto | — | ACME renew helper | `RenewIfNeeded(ctx, profile, store)` using `renew_before` | No-op when not due; re-issue when due |
| **W60-04** | P1 | Complete | L | cli | W60-01, W60-02 | CLI `acme register\|issue\|status\|doctor` | Cobra group; flags for directory/staging/email/TOS/solvers/out paths | Staging or Pebble issue succeeds in manual test |
| **W60-05** | P1 | Complete | M | crypto | W60-04 | HTTP-01 listen + webroot solvers for CLI | Reuse/adapt `MemoryHTTP01` + host listen/webroot | Present/cleanup on loopback or webroot path |
| **W60-06** | P1 | Complete | M | crypto | W60-04 | Wire DNS-01 Cloudflare + webhook for CLI | Same providers as operator | Issue with CF or webhook in lab |
| **W60-07** | P1 | Complete | M | cli | W60-03, W60-04 | CLI `acme renew` + post-renew hook | `--all` / profile; exec hook on success | Hook runs only after successful write |

### Phase B — Standalone productization

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W60-08** | P1 | Complete | S | docs | W60-04 | ACME profile YAML + examples | `/etc/knxvault/acme.d/` example; LE staging defaults | Example file in `config/` or `examples/acme/` |
| **W60-09** | P1 | Complete | S | docs | W60-07, W60-08 | Standalone + build docs for public TLS | Update standalone Day-0/Day-2, build-and-deploy, support matrix | Matrix: standalone ACME = Yes via CLI |
| **W60-10** | P1 | Complete | S | docs | W60-08 | systemd timer/unit examples | `knxvault-acme-renew.timer` calling CLI renew | Units under `deployments/systemd/` or `examples/` |
| **W60-11** | P1 | Complete | S | security | W60-04 | ACME doctor + LE SkipTLSVerify guard | Reject skip-verify for public LE hosts; doctor checks perms/TOS | Unit test blocks LE + InsecureSkipVerify |

### Phase C — Kubernetes alignment

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W60-12** | P1 | Complete | S | docs | W60-09 | K8s CLI guide ACME section | Operator vs host CLI edge; staging→prod | kubernetes-cli-day0-day2 + cli reference updated |
| **W60-13** | P2 | Complete | M | k8s | W60-03 | Operator uses shared renew helper | Deduplicate renew policy with CLI | Operator renew behavior covered by unit tests |
| **W60-14** | P2 | Partial | M | ci | W60-05 | Pebble (or staging) integration test | Optional CI job; not flaky public LE | Test passes in lab CI profile |

### Phase D — Stretch (milestone M-ACME-2)

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W60-15** | P2 | Complete | S | docs | M-ACME-1 | ADR: vault-stored ACME state | Accept or reject Raft ACME state | ADR merged |
| **W60-16** | P2 | Partial | L | api | W60-15 | Optional ACME state API + CLI `--store=vault` | Encrypted account/cert metadata in knxvault | RBAC + seal-aware |
| **W60-17** | P2 | Complete | M | cli | W60-07 | Long-running `acme agent` / subcommand | Poll renew without systemd | Documented; optional binary |

> **M-ACME-1 sequencing:** **W60-01–W60-03** (library) → **W60-04–W60-07** (CLI) → **W60-08–W60-11** (standalone docs/hardening) → **W60-12–W60-14** (K8s/docs/CI). Do not start **W60-16** until **W60-15** ADR accepts vault storage.

---

## Milestone M-DNS01-1 — DNS-01 providers and webhooks (cert-manager parity)

**Status:** Not started (design 2026-07-17).  
**Design:** [`docs/design/dns01-providers-and-webhooks.md`](design/dns01-providers-and-webhooks.md)  
**Depends on:** M-ACME-1 core (`internal/acme`, operator ACME, CLI).  
**Priority:** **P1**.

| Field | Value |
|-------|-------|
| **Claim when done** | DNS-01: registry + webhook v1 + multi-solver selectors; CF hardened; webhook template for out-of-tree providers (Route53/RFC2136 optional in-tree) |
| **Phases** | **A** registry/webhook · **B** CRD solvers · **C** providers/templates · **D** CI/harden |
| **Exit** | Design §8 acceptance criteria |

### Phase A — Registry + webhook v1

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W61-01** | P1 | Not started | M | crypto | M-ACME-1 | Provider registry | `providers.Register` / factory by name for memory, cloudflare, webhook | Unit tests; operator + CLI use registry |
| **W61-02** | P1 | Not started | M | crypto | W61-01 | Webhook protocol v1 | Additive JSON: `apiVersion`, `config`, `key`; keep old body | Dual-read tests |
| **W61-03** | P1 | Not started | M | security | W61-02 | Webhook bearer auth | SecretKeyRef / file token → Authorization header | 401 surfaces clear error |
| **W61-04** | P1 | Not started | S | security | W61-02 | Webhook URL allowlist | Optional allowlist; default SSRF validation | Unit tests |
| **W61-05** | P1 | Not started | M | cli | W61-02, W61-03 | CLI profile webhook config | `webhook_config` / auth token file in ACME profile | Example under `examples/acme/` |
| **W61-06** | P1 | Not started | S | observability | W61-01 | DNS-01 metrics + logs | `*_dns01_present_total{provider}`; no secrets in logs | Metrics registered |

### Phase B — Multi-solver CRD + Cloudflare

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W61-07** | P1 | Not started | L | k8s | W61-01 | CRD `acme.solvers[]` + selectors | `dnsZones` / `dnsNames`; legacy `dns01` still works | DeepCopy + unit tests |
| **W61-08** | P1 | Not started | M | k8s | W61-07 | Operator solver selection | Pick first matching solver for certificate domain | Selector unit tests |
| **W61-09** | P1 | Not started | M | crypto | W61-01 | Cloudflare harden | TTL, multi-TXT cleanup, zone match, backoff | Unit tests with httptest |
| **W61-10** | P2 | Not started | S | k8s | W61-07 | cmcompat DNS01 webhook map | Document + map cert-manager webhook fields | Mapping table in docs |
| **W61-11** | P1 | Not started | S | docs | W61-07, W61-05 | DNS-01 operator + CLI guide | Solvers, secrets, staging, webhook install | Matrix + runbook updated |

### Phase C — In-tree providers and webhook template

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W61-12** | P2 | Not started | L | crypto | W61-01 | In-tree RFC2136 (TSIG) | Optional first-party dynamic DNS | Mock tests; permissive license |
| **W61-13** | P2 | Not started | L | crypto | W61-01 | In-tree Route53 | Optional; raw SigV4 preferred over heavy SDK | License gate pass |
| **W61-14** | P1 | Not started | M | k8s | W61-02 | Webhook Deployment template | `deployments/acme-dns-webhook-template/` + sample handler docs | README applies on kind |
| **W61-15** | P1 | Not started | S | docs | W61-14 | Provider catalog | In-tree vs webhook-only list | Doc in operations/ |

### Phase D — CI and hardening

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W61-16** | P1 | Not started | M | ci | W61-02 | Mock webhook integration test | CI-safe Present/CleanUp + ACME path | Test in `make test` or labeled CI |
| **W61-17** | P2 | Not started | S | crypto | W61-01 | Propagation wait / TTL knobs | Configurable delay before ACME Accept | Unit-configurable |
| **W61-18** | P1 | Not started | S | security | W61-03 | Out-of-tree webhook security checklist | Threat model for webhook authors | Doc published |

> **M-DNS01-1 sequencing:** **W61-01–W61-06** (contract) before **W61-07–W11** (CRD). Prefer **W61-14/15** (webhook ecosystem) over rushing **W61-12/13** if capacity is tight. Milestone can exit without Route53/RFC2136 if webhook template + multi-solver ship.

---

## Milestone M-PRODSEC-1 — Production security posture (set-and-forget + safer defaults)

**Status:** Partial — **A1 profile fail-closed shipped** (W62-01/02/04, 2026-07-17). Remaining: doctor, kustomize, bootstrap root death.  
**Design:** [`docs/design/production-security-posture.md`](design/production-security-posture.md)  
**Assessment baseline:** [`docs/architecture/security-posture-assessment.md`](architecture/security-posture-assessment.md)  
**Closes:** Production “set and forget” Medium; root/ClusterIssuer DIY footguns; encodes operator-security checklist into product.

| Field | Value |
|-------|-------|
| **Claim after exit** | Production profile **fails closed** on lab/insecure config; Day-0 ends with **no live root** and **SA-only operator**; `doctor --profile production` is the install gate |
| **Phases** | **A** profile + doctor · **B** manifests + operator · **C** bootstrap root death · **D** docs/e2e |

### Phase A — Profile + doctor

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| ~~**W62-01**~~ | P0 | **Complete** | M | security | — | `security.profile` / `KNXVAULT_SECURITY_PROFILE` | `lab` \| `production`; wire into config load | Done — env + YAML `security.profile`; default lab |
| ~~**W62-02**~~ | P0 | **Complete** | M | security | W62-01 | Production `ValidateSecurity` | Reject insecure k8s auth, Raft multi-node without mTLS, missing audit signing / metrics bearer; TLS or ingress; valkey shape; root TTL cap 4h | Done — `internal/config/security.go` + table tests; multi-node counts `InitialMembersRaw` |
| **W62-03** | P0 | Not started | M | cli | W62-02 | `doctor --profile production` | Fail (not warn) on root-alive, no TLS, no Raft mTLS, insecure flags, no audit signing | CLI tests + docs |
| ~~**W62-04**~~ | P1 | **Complete** | S | docs | W62-01 | `config/knxvault.production.yaml` | Production defaults: rate limit on, insecure off, profile production | Done — file + configuration.md + example YAML |

### Phase B — Production pack + operator defaults

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W62-05** | P0 | Not started | M | k8s | W62-01 | `deployments/k8s/production/` kustomize | NetworkPolicy, metrics bearer/Service, base STS overlay with production profile | `kubectl apply -k` documented |
| **W62-06** | P0 | Not started | M | k8s | W62-05 | Issuer / ClusterIssuer RBAC | Only platform ns/group can create ClusterIssuer; sample Roles | Manifest + operator-security update |
| **W62-07** | P0 | Not started | S | k8s | — | Operator samples SA-only | Root-token operator path lab-only; production samples use K8s role | Samples + runbook |
| **W62-08** | P1 | Not started | M | k8s | W62-02, W62-07 | Operator production fail-closed | Refuse static root when profile=production (or operator flag `production`) | Unit/integration test |

### Phase C — Bootstrap root death

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W62-09** | P0 | Not started | M | auth | W62-01 | Short prod root TTL + non-renewable option | Production profile default root TTL 1–4h (configurable) | Config + token tests |
| **W62-10** | P0 | Not started | L | auth | W62-09 | Bootstrap complete API/Job | `POST /sys/bootstrap/complete` (or equivalent) revokes root after admin+operator roles exist | API test; audit event |
| **W62-11** | P1 | Not started | M | k8s | W62-10, W62-07 | Bootstrap Job manifest | Creates operator role policies; calls complete; no root left in STS env | Day-0 doc + kind smoke |

### Phase D — Docs, golden path, regression

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W62-12** | P0 | Not started | M | docs | W62-03, W62-05, W62-10 | Golden-path Day-0 | Single production narrative; lab paths labeled | operator-runbook + install + kubernetes-cli updated |
| **W62-13** | P1 | Not started | S | docs | W62-12 | Migration: revoke cert-manager tokens | Dual-run teardown checklist | pki-replace-cert-manager section |
| **W62-14** | P1 | Not started | M | ci | W62-02, W62-03 | Posture e2e | Integration: bad prod config fails start; doctor fail cases | `make test-integration` or labeled job |
| **W62-15** | P1 | Not started | S | security | W62-02 | Past Critical/High regression map | Link audit findings to permanent tests (index doc) | `docs/audit/` or engineering note |

> **M-PRODSEC-1 sequencing:** **W62-01–04** then **W62-05–08** in parallel with **W62-09–11**. Exit without KMS (that is **M-CUSTODY-1**). Align Issuer webhook allowlist implementation with **W61-03/04** when both in flight.

---

## Milestone M-CUSTODY-1 — KMS / HSM custody

**Status:** Partial — **W63-01 complete** (aes-kek auto-unseal; cloud KMS supplies KEK via CSI, no embedded cloud SDK).  
**Design:** [`docs/design/production-security-posture.md`](design/production-security-posture.md) §6 / §8 Phase 1.  
**Depends on:** M-PRODSEC-1 profile concepts helpful but not hard-blocked for design spikes.

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| ~~**W63-01**~~ | P1 | **Complete** | L | crypto | — | KMS auto-unseal (aes-kek) | Unwrap unseal key via injected KEK (cloud KMS CSI) at start | Unit tests seal/decrypt; env `KNXVAULT_AUTO_UNSEAL_*` |
| **W63-02** | P1 | Not started | L | crypto | W63-01 | KMS-wrapped master key | Master ciphertext at rest; unwrap for envelope crypto | Restart + decrypt secrets without plain master in Secret |
| **W63-03** | P1 | Not started | M | docs | W63-01 | Custody + break-glass runbook | Ceremony, IAM split, recovery | `docs/operations/` runbook |
| **W63-04** | P2 | Not started | XL | crypto | W63-02 | PKCS#11 CA keys | Optional offline root/intermediate | Design + PoC; license-safe PKCS#11 path |
| **W63-05** | P2 | Not started | M | security | W63-01 | Production profile + KMS | Prod profile can require KMS unseal when configured | ValidateSecurity rules |

> Prefer **W63-01** before **W63-04**. Do not block M-PRODSEC-1 on HSM.

---

## Milestone W77 — Three-cycle security audit (2026-07-17)

**Status:** **Complete**.  
**Report:** [`docs/audit/security-remediation-w77-3cycle-2026-07-17.md`](audit/security-remediation-w77-3cycle-2026-07-17.md)

| ID | Status | Title |
|----|--------|-------|
| ~~W77-01~~ | **Complete** | Cert login fail-closed (stored roles only) |
| ~~W77-02~~ | **Complete** | KV soft-delete hides latest |
| ~~W77-03~~ | **Complete** | Token max lifetime on Issue/Create |
| ~~W77-04~~ | **Complete** | OCSP seal guard |
| ~~W77-05~~ | **Complete** | Login seal guard |
| ~~W77-06~~ | **Complete** | Listener TLS path jail |
| ~~W77-07~~ | **Complete** | Exposure sealed skip |
| ~~W77-08~~ | **Complete** | Glob single-segment `*` |

## Milestone W76 — Three-cycle security remediation (2026-07-17)

**Status:** **Complete** (3 review cycles).  
**Report:** [`docs/audit/security-remediation-w76-3cycle-2026-07-17.md`](audit/security-remediation-w76-3cycle-2026-07-17.md)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| ~~W76-01~~ | P0 | **Complete** | Unseal CIDR fail-closed |
| ~~W76-02~~ | P0 | **Complete** | Seal-aware JobRunner |
| ~~W76-03~~ | P0 | **Complete** | Webhook SSRF + SafeHTTPClient |
| ~~W76-04~~ | P0 | **Complete** | DB/SSH tenant lease renew/revoke |
| ~~W76-05~~ | P0 | **Complete** | Path-safe lease ID prefix (`ns.id`) |
| ~~W76-06~~ | P1 | **Complete** | Tenant lease empty-ns fail-closed |
| ~~W76-07~~ | P1 | **Complete** | Cert login privileged CN guard |

## Milestone W75 — CIS hardening (network, defaults, multi-tenant stance)

**Status:** **Complete** (P0–P3 / 2026-07-17).  
**Design:** [`docs/design/cis-hardening-improvements.md`](design/cis-hardening-improvements.md)

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| ~~**W75-01**~~ | P0 | **Complete** | S | security | W62-01 | Multi-node Raft forces production profile | Auto-upgrade lab→production unless `RAFT_ALLOW_INSECURE` | Unit tests force + lab escape |
| ~~**W75-02**~~ | P0 | **Complete** | M | k8s | W75-01 | Production kustomize overlay | NetPol ingress+egress sketch, profile ConfigMap, README | `kubectl apply -k deployments/k8s/production` documented |
| ~~**W75-03**~~ | P1 | **Complete** | M | api | — | Metrics listen address split | `KNXVAULT_METRICS_ADDR`; dedicated Service :8201 | Config + production overlay |
| ~~**W75-04**~~ | P1 | **Complete** | M | security | W75-02 | Unseal source CIDR allowlist | `KNXVAULT_UNSEAL_ALLOW_CIDRS` + NetPol unseal-client | Unit tests + handler check |
| ~~**W75-05**~~ | P1 | **Complete** | M | k8s | W75-02 | ACME egress NetPol sample | `networkpolicy-acme-egress.yaml` | Overlay includes sample |
| ~~**W62-03**~~ | P0 | **Complete** | M | cli | W62-02 | `doctor --profile production` | TLS scheme fail, token required, metrics plane note | doctor tests |
| ~~**W75-06**~~ | P1 | **Complete** | S | docs | W75-02 | Day-0 docs prefer production kustomize | CIS design + production README + config ref | Docs updated |
| ~~**W75-07**~~ | P2 | **Complete** | S | docs | W64-00 | Hard isolation runbook | multi-tenant.md + ADR-0011 | Ops doc |
| ~~**W63-01**~~ | P1 | **Complete** | L | crypto | — | Auto-unseal aes-kek | `KNXVAULT_AUTO_UNSEAL_*` decrypt + unseal on start | Unit tests seal/decrypt |
| ~~**W64-00**~~ | P2 | **Complete** | S | docs | — | Product decision single-tenant default | ADR-0011 | Accepted |
| ~~**W64-01**~~ | P2 | **Complete** | M | auth | W64-00 | Tenant-prefix lease IDs | DB/SSH stamp + LeaseService check | Unit tests |

## Optional — Multi-tenant SaaS isolation (W64)

**Status:** **W64-00/01 complete** (single trust domain default + soft tenant lease IDs). Remaining rows only if multi-customer SaaS is a product goal.  
**Design:** production-security-posture §6.2; [ADR-0011](adr/0011-multi-tenant-stance.md); [multi-tenant.md](operations/multi-tenant.md). Full capability context: [vault-class-capability-plan.md](design/vault-class-capability-plan.md) §6.16.

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| ~~**W64-00**~~ | P2 | **Complete** | S | docs | — | Product decision record | Single-tenant platform default; soft mode optional | ADR-0011 accepted |
| ~~**W64-01**~~ | P2 | **Complete** | M | auth | W64-00 | Tenant-prefix lease IDs | Close W53 cross-tenant renew residual | Tests deny cross-tenant lease |
| **W64-02** | P2 | Not started | M | auth | W64-01 | Tenant quotas + rate limits | Per-tenant caps | Config + tests |
| **W64-03** | P2 | Not started | L | storage | W64-00 SaaS | Optional per-tenant cluster mode | True isolation when ADR-0005 insufficient | Design + PoC doc |
| **W64-04** | P2 | Not started | M | audit | W64-01 | Tenant-scoped audit export | Filter export by tenant | API + test |

---

## Vault-class capability program (W65–W73)

**Status:** Not started (design 2026-07-17).  
**Design / plan:** [`docs/design/vault-class-capability-plan.md`](design/vault-class-capability-plan.md)  
**Principles:** no binary plugins; cloud IAM/auth deferred (LT-02/LT-15); SAML via IdP→OIDC; Sentinel→OPA/native policy.

> **Sequencing:** **W67** (leases) before **W66** (wrap) and **W69** (dyn engines). **W65** (transit) can parallel W66 after crypto review. **W71** before **W68**. **W63** parallel after W62. Do **not** start LT-02/LT-15 without a new product decision.

### M-LEASE-1 — Unified lease framework (W67)

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W67-01** | P0 | **Complete** | M | crypto | — | LeaseService + OnRevoke hooks | Single registry; DB/SSH call hooks | Unit tests; engines use registry only |
| **W67-02** | P0 | **Complete** | M | api | W67-01 | Sys lease list/lookup/renew/revoke/tidy | REST + OpenAPI | Handler tests |
| **W67-03** | P0 | **Complete** | M | auth | W67-01 | Cascade revoke on token revoke | Leases owned by token revoked | Integration test |
| **W67-04** | P1 | **Complete** | S | observability | W67-02 | Lease metrics + audit | active_leases accurate | Metrics + audit actions |
| ~~**W67-05**~~ | P1 | **Complete** | M | auth | W67-01, W64-01 | Tenant-safe lease IDs | Align tenant mode | Cross-tenant renew denied |

### M-WRAP-1 — Cubbyhole + response wrapping (W66)

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W66-01** | P0 | **Complete** | M | crypto | — | Cubbyhole engine | Per-token private KV; wipe on revoke | Unit tests |
| **W66-02** | P0 | **Complete** | M | api | W66-01 | Response wrap mint | Header/flag → wrapping token | Single-use; TTL |
| **W66-03** | P0 | **Complete** | S | api | W66-02 | Unwrap (+ optional lookup) | `POST /sys/wrapping/unwrap` | OpenAPI + tests |
| **W66-04** | P1 | **Complete** | S | docs | W66-03 | Wrap bootstrap recipe | Docs recipe | Recipe published |

### M-TRANSIT-1 — Transit EaaS (W65)

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W65-01** | P0 | **Complete** | L | crypto | — | Transit keys + encrypt/decrypt/rotate | Envelope-stored keys; versioned ciphertext | Round-trip + rotate tests |
| **W65-02** | P1 | **Complete** | M | crypto | W65-01 | Sign / verify / HMAC | Asymmetric + HMAC ops | Unit tests |
| **W65-03** | P1 | **Complete** | M | api | W65-01 | Handlers + RBAC + OpenAPI | Path capabilities | Handler tests |
| **W65-04** | P1 | **Complete** | S | docs | W65-03 | Transit guide + recipe | User docs | Docs linked from README |
| **W65-05** | P2 | Not started | L | crypto | W65-01 | Transform/tokenization decision | Narrow FPE or external | ADR + implement or defer note |

### M-JWT-1 — JWT variants + GitHub (W71)

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W71-01** | P1 | Not started | M | auth | — | Generic JWT auth roles + login | iss/aud/claims → policies | Bound-claims tests |
| **W71-02** | P1 | Not started | S | docs | W71-01 | GitHub Actions OIDC recipe | Prefer OIDC over PAT | Recipe published |
| **W71-03** | P2 | Not started | M | auth | W71-01 | Optional GitHub token method | Only if OIDC insufficient | Tests + docs |

### M-IDENT-1 — Identity entity/group (W68)

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W68-01** | P1 | **Complete** | L | auth | — | Entity/alias/group domain + Raft | CRUD | Unit tests |
| **W68-02** | P1 | **Complete** | M | auth | W68-01, W71-01 | Login merges group policies | entity_id on token | Multi-auth test |
| **W68-03** | P1 | **Complete** | M | auth | W68-01 | NHI / agent → entity | Migration note | Tests |
| **W68-04** | P1 | **Complete** | S | docs | W68-02 | Identity API docs | OpenAPI + guide | Docs |

### M-DYN-1 — Curated dynamic engines (W69)

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W69-01** | P1 | Not started | S | docs | W67-01 | Engine contribution checklist | Leases, licenses, tests | engineering/ doc |
| **W69-02** | P1 | Not started | L | crypto | W67-01 | First new engine (e.g. Redis/Valkey) | Creds + revoke + lease | Tests + recipe |
| **W69-03** | P2 | Not started | L | crypto | W69-02 | Second engine optional | Same bar | Tests |

### Optional LDAP (W70)

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W70-01** | P2 | **Complete** | S | docs | — | IdP → OIDC for LDAP/AD | Preferred path | Guide published |
| **W70-02** | P2 | **Complete** | L | auth | — | Native LDAP auth | Only if no IdP | Bind + group map tests |

### M-DR-1 — Disaster recovery (W72)

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W72-01** | P1 | Not started | M | ops | — | Backup ship to object storage | CronJob/script | Lab restore from object store |
| **W72-02** | P1 | Not started | M | docs | W72-01 | Promote runbook + RPO/RTO | Ops doc | Published |
| **W72-03** | P2 | Not started | L | storage | W72-01 | Optional continuous async ship | Not Vault streaming PR | Design + flag |

### M-SYNC-1 — Secret sync (W73)

| ID | Priority | Status | Effort | Area | Depends on | Title | Description | Acceptance criteria |
|----|----------|--------|--------|------|------------|-------|-------------|---------------------|
| **W73-01** | P1 | **Complete** | S | docs | — | CSI vs ESO vs wrap matrix | Decision guide | Docs |
| **W73-02** | P2 | Not started | L | k8s | W73-01 | Push-sync controller optional | One external store PoC | On-demand only |

---

## Post-quantum readiness (separate backlog)

Tracked under **[`docs/pq/backlog.md`](pq/backlog.md)** with IDs **PQ-01…PQ-93** (phases PQ-0 document/harden through PQ-5 optional KEM wrap). Design: dual crypto planes, generations **g1** (classical default for Harbor/legacy) / **g2+** (opt-in). Index: [`docs/pq/README.md`](pq/README.md).

## Long-term future

Deferred packaging and ecosystem work — not scheduled for Tier 0 / Phase 4–5 near-term delivery. Revisit after **W37** checklist items and **W36** hardening stabilize.

| Item | Area | Rationale |
|------|------|-----------|
| **Helm chart** | k8s | Deferred as **LT-03**. Near-term: raw manifests in `deployments/k8s/` (**W28-02**). |
| **Cloud dynamic secrets (AWS/Azure/GCP IAM)** | crypto | Deferred as **LT-02**. **Not required near-term** (product decision 2026-07-17). Near-term: database + SSH dynamic engines + OIDC/K8s/AppRole auth. |
| **Cloud auth methods (AWS IAM, Azure MSI, GCP)** | auth | Deferred as **LT-15**. **Not required near-term** (same decision). Prefer K8s SA, AppRole, OIDC/JWT. |
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
| **LT-02** | Cloud dynamic secrets engines (AWS / Azure / GCP IAM) | crypto | XL | W37-02, W36-20 | **Not required near-term (2026-07-17).** LLD §9.4 cloud OAuth/IAM engines. Scaffold later: e.g. `internal/engine/secrets/aws/` + STS `AssumeRole`, Azure/GCP equivalents, lease revoke. **Do not schedule** ahead of transit/wrapping/leases/KMS unseal or M-PRODSEC. Near-term: KV + database + SSH. | When revived: temporary cloud creds + lease docs + sandbox test per cloud. |
| **LT-15** | Cloud auth methods (AWS IAM, Azure MSI, GCP) | auth | XL | W37-02 | **Not required near-term (2026-07-17).** Verify cloud identity docs / metadata-bound tokens → policies. Prefer **OIDC/JWT** and **Kubernetes SA** instead. Schedule only if non-K8s cloud VMs must login without an IdP. Plan: [vault-class-capability-plan.md](design/vault-class-capability-plan.md) §6.7. | When revived: one cloud PoC maps instance/role → client token; audit + lockout. |
| **LT-16** | KMIP server or façade | crypto | XL | W65-01 | **External KMIP preferred.** Optional thin façade over Transit later. Do not schedule near-term. | Decision note or external integration doc. |
| **LT-17** | Performance scale-out (not Vault PR) | storage | XL | Phase 3 stable | **Not** Vault Performance Replication. Options: vertical scale, Raft learners if supported, multi-cluster. | Design ADR if product requires multi-region reads. |
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