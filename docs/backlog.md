# KNXVault Backlog

Actionable backlog derived from [`docs/lld.md`](lld.md). Items are **topologically sorted by dependency** — implement in listed order within each phase.

**Current focus:** [Tier 0 — Secrets manager checklist](#tier-0--secrets-manager-checklist-priority-0) (W37-01–W37-10) closes market-fit gaps vs. enterprise secrets managers. Then [Tier A–E hardening](#tier-a--security-blockers-do-first) (W36-01–W36-24). Phase 5 (W30–W35) ecosystem work follows.

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

Items below come from a **2026-06 codebase gap analysis** (Phases 1–3 complete; not production-hardened) and a **secrets manager checklist** comparison (encryption, rotation, NHI, exposure detection, integrations). Implement **Tier 0 first**, then Tiers A–E, before Phase 5 ecosystem work. Descriptions include **file hints** (`path:symbol`) to start quickly.

### Tier 0 — Secrets manager checklist (Priority 0)

**Take these up before Tier A.** Maps to common secrets-manager evaluation criteria (encryption in transit, automated rotation, NHI/AI agents, dynamic credentials, exposure detection, enterprise integrations). Several items depend on **W36-01** (fail-closed auth) and **W36-04** (master key required) — implement those in parallel if blocked.

| ID | Checklist criterion | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|---------------------|-------|------|--------|------------|-------------|---------------------|
| **W37-01** | Encryption in transit | Server TLS and optional mTLS | security | M | W36-04 | **Gap:** Server is plain HTTP (`internal/app/app.go:59–61`); security model defers TLS to ingress only. **Hint:** Add `KNXVAULT_TLS_CERT`, `KNXVAULT_TLS_KEY`, `KNXVAULT_MTLS_REQUIRED`, `KNXVAULT_MTLS_CA` to `internal/config/config.go`. Wrap `http.Server` with `tls.Config` in `internal/app/app.go`; add client-cert middleware in `internal/api/middleware/` (extract `tls.ConnectionState.PeerCertificates`). Supersedes priority of Phase 5 **W34-01**. | HTTPS listener works; with `MTLS_REQUIRED=true`, `/secrets/kv/*` rejects requests without valid client cert. Integration test with generated CA + leaf. |
| **W37-02** | Short-lived credentials | OIDC/JWT auth method | auth | L | W36-01, W36-13 | **Gap:** Only opaque tokens + K8s HS256 stub (`internal/auth/token.go`); no OIDC for CI/CD (GitHub Actions, GitLab) or cloud workload identity. **Hint:** New `POST /auth/oidc/:role` handler in `internal/api/handlers/auth.go`. Config per role: `issuer`, `audience`, `jwks_url` or pinned JWKS in Raft `auth_method` entity. Validate RS256/ES256 via `github.com/MicahParks/keyfunc` or `coreos/go-oidc`. Issue **short TTL** client token (default 1h, max from role). Store auth method config via new Raft commands or extend `role.save`. | GitHub Actions OIDC JWT exchanges for scoped token; wrong `aud`/`iss` rejected. Document in `docs/integration/overview.md`. |
| **W37-03** | NHI — machine identities | Machine identity registry (NHI) | auth | L | W36-02, W36-03, W36-13 | **Gap:** No first-class non-human identity (NHI) model — only generic roles/tokens. **Hint:** Add `MachineIdentity` domain (`internal/domain/auth/machine_identity.go`): `id`, `type` (k8s_sa \| oidc \| api_key), `bound_namespace`, `bound_name`, `policies`, `max_ttl`, `last_seen`. Raft commands `machine_identity.save` / `list` / `revoke`. Login flows (TokenReview, OIDC) resolve to machine identity record and emit audit `nhi.login`. Expose `GET /sys/machine-identities` for operators. | K8s SA login creates/updates machine identity row; revoke identity blocks future logins. Audit export includes NHI actor type. |
| **W37-04** | NHI / AI agents | AI agent scoped auth & delegation | auth | M | W37-02, W37-03 | **Gap:** No agent-specific vaults, delegation chains, or tool-scoped policies for autonomous workloads. **Hint:** Extend `MachineIdentity` with `parent_identity_id` and `allowed_actions[]` (e.g. `secrets/kv:read:agent/*` only). Add `POST /auth/agent/delegate` — parent token mints child token with **narrower** policies and **shorter TTL** (cap 15m). Policy condition `agent_id` in `internal/auth/evaluator.go`. Optional KV path prefix `agent/{identity_id}/*` enforced in middleware. | Parent CI token delegates 15m agent token; agent cannot access paths outside prefix. Delegation audited with parent→child link. |
| **W37-05** | Automated rotation | Scheduled KV secret rotation | crypto | M | W36-05, W36-17 | **Gap:** KV supports TTL expiry (`internal/engine/secrets/kvv2.go:95–101`) but no **scheduled value rotation** (rewrite secret on cron). **Hint:** Add `RotationPolicy` on secret metadata or parallel `rotation_policy` Raft entity: `path`, `interval`, `generator` (`random_password` \| `script_ref`). Leader job in `internal/app/jobs.go` (new `runKVRotation`) reads policies, generates new value, `Put` with new version, audits `secret.rotate`. API: `PUT /secrets/kv/:path/rotation` + `DELETE` to disable. | Policy `interval: 24h` produces new KV version daily; old versions retained per `max_versions`. Job runs only on Raft leader. |
| **W37-06** | Automated rotation | End-to-end rotation orchestration | crypto | L | W37-05, W36-18 | **Gap:** DB engine returns SQL (client mode); managed mode missing; no unified “rotate and notify consumers” flow. **Hint:** After W36-18 managed DB mode: rotation job calls `database.Engine.RotateLease` for leases nearing expiry. Add `POST /sys/rotation/run` (admin) to trigger all engines. Webhook notifier interface `internal/notify/webhook.go` — POST JSON `{event, path, lease_id}` on rotation success (K8s Job, Argo, custom). Wire optional `rotation_webhook_url` in ConfigMap. | DB lease auto-renewed before TTL; KV rotated per W37-05; webhook receives event; audit trail links old→new version/lease. |
| **W37-07** | Exposure detection | Secret exposure webhook & auto-remediation hooks | security | L | W37-05, W36-17 | **Gap:** No integration with secret scanners (GitGuardian, Gitleaks, TruffleHog) — vault cannot react to leaks in repos/logs/chat. **Hint:** `POST /sys/exposure/report` (HMAC-signed or mTLS) accepts `{detector, fingerprint, secret_path?, lease_id?, severity}`. Handler audits `exposure.reported`, optionally: (1) revoke DB lease, (2) trigger W37-05 rotation for KV path, (3) fire webhook. Config `exposure_auto_revoke: true`. Document pairing with external scanners in `docs/integration/exposure-detection.md` (new). **Out of scope:** building a scanner — integration only. | Simulated report revokes lease + rotates KV; audit shows remediation actions. Unsigned report rejected. |
| **W37-08** | Integrations | Helm chart (production install) | k8s | M | W28-02, W37-01 | **Gap:** Only raw manifests (`deployments/k8s/`); Helm deferred since Phase 1. **Hint:** Scaffold `deployments/helm/knxvault/` per LLD §6.1: `values.yaml` with `raft.*`, `persistence`, `tls`, `resources`; StatefulSet template from `statefulset.yaml`; optional `pre-upgrade` Job hook calling `POST /sys/backup`. Move long-term future item into active delivery. | `helm install` brings 3-node Raft cluster; `helm upgrade` runs backup hook; README updated. |
| **W37-09** | Integrations | Multi-language SDK via OpenAPI codegen | docs | M | W8-03 | **Gap:** Only Go `pkg/client` — no officially blessed Python/Node/Java clients. **Hint:** Add `make generate-clients` using `openapi-generator` against `api/openapi.yaml`; output to `clients/python`, `clients/typescript` (or separate repos). Pin generated version to release tag. Extend `pkg/client` coverage to match full OpenAPI (policies, database, audit). Document in `docs/integration/overview.md`. | Python + TS clients pass smoke tests (health, kv put/get, auth). CI job verifies codegen drift. |
| **W37-10** | Checklist / docs | Secrets manager capability matrix | docs | S | W37-01–W37-07 | **Gap:** No single doc mapping product vs. evaluation checklist. **Hint:** Add `docs/product/secrets-manager-checklist.md` — table: criterion → status (yes/partial/planned) → backlog ID → doc link. Update `docs/README.md` index. Reconcile after each W37 ship. | Matrix covers all 10 checklist items; no “implemented” without code or ADR reference. |

> **Tier 0 sequencing:** **W37-01** (TLS) + **W37-02** (OIDC) unblock most NHI/dynamic-cred work. **W37-07** (exposure) can start after rotation hooks (**W37-05**). **W37-08–W37-09** (Helm + SDKs) can parallelize once Tier A auth blockers (**W36-01–W36-04**) land. **At rest encryption** is already implemented (envelope + Raft); no W37 item — maintain via **W36-04**. Near-term dynamic creds: database engine (W12) + OIDC (W37-02). **Terraform** (**LT-01**) and **cloud IAM dynamic secrets** (**LT-02**) are deferred to [long-term future](#long-term-future).

### Tier A — Security blockers (do first)

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| **W36-01** | Fail closed on K8s login without JWT validation | security | S | W7-03 | **Hint:** `internal/auth/token.go:LoginKubernetes` — when `len(s.jwtSecret)==0`, it currently issues tokens with **no** JWT crypto check (any `role` + arbitrary JWT string works). Reject with `401` unless a validation path is configured. Add `config` guard: production (`KNXVAULT_RAFT_ENABLED=true`) must not allow unvalidated K8s login. | Unit test: empty `KNXVAULT_JWT_SECRET` + `POST /auth/kubernetes` → `401`. Dev mode (`RAFT_ENABLED=false`) may keep opt-in bypass behind explicit `KNXVAULT_K8S_AUTH_INSECURE=true`. |
| **W36-02** | Kubernetes TokenReview authentication | auth | M | W36-01 | **Hint:** Replace HS256 stub in `internal/auth/token.go:LoginKubernetes` (lines 137–154) with `authentication.k8s.io/v1` **TokenReview** via client in `internal/infra/k8s/`. Real SA tokens are RS256 from the API server — HS256 + `KNXVAULT_JWT_SECRET` is dev-only. Parse `status.user.username`, `groups`, SA namespace/name from review response. Wire SA token from `Authorization: Bearer` or request body `jwt`. | Integration test with fake TokenReview server OR env-gated live cluster test. Real K8s SA JWT (RS256) authenticates; forged JWT rejected. Update `docs/architecture/security-model.md` to distinguish dev HS256 vs prod TokenReview. |
| **W36-03** | ServiceAccount binding on roles | auth | M | W36-02 | **Hint:** Docs mention `bound_service_account_names` / `bound_service_account_namespaces` (`docs/user/getting-started.md`) but `internal/domain/auth/role.go` has no fields. Extend `Role` domain + Raft `role.save` payload; after TokenReview, match `system:serviceaccount:<ns>:<name>` against role bindings before `tokens.Issue`. | Role bound to `app` SA in `prod` ns: login with matching SA succeeds; wrong SA or namespace → `403`. Persisted via Raft; unit + integration tests. |
| **W36-04** | Require master key when Raft enabled | security | S | W3-01, W26-01 | **Hint:** `internal/app/deps.go:76–85` logs a warn and continues without crypto when `masterkey.Load()` fails. ADR-0003 says master key required. In `NewDependencies`, return error (fail startup) when `cfg.Raft.Enabled && deps.Crypto == nil`. In-memory dev mode (`RAFT_ENABLED=false`) may remain permissive. | `KNXVAULT_RAFT_ENABLED=true` without `KNXVAULT_MASTER_KEY` → process exits non-zero. Existing `deps_test` updated. Document in `docs/installation/configuration.md`. |
| **W36-05** | Atomic KV write in Raft state machine | storage | M | W25-01 | **Hint:** Race in `internal/engine/secrets/kvv2.go` — `NextVersion` then `SaveVersion` are **two** Raft ops; `OpSecretNextVersion` is read-only (`internal/raft/commands.go:73`). Add `secret.put` command: allocate version + CAS check + save inside `internal/raft/store.go:Handle` in one `Update`. Dragonboat repo: single `Propose` from `internal/repository/dragonboat/repo.go`. Deprecate split path or retry on `version already exists`. | Concurrent `Put` same path (10 goroutines) under 3-node Raft: all versions unique, no lost writes. `internal/raft/store_test.go` covers atomic put. |

### Tier B — Raft correctness & HA confidence

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| **W36-06** | Include audit log in Dragonboat snapshots | storage | M | W25-01 | **Hint:** `internal/raft/statemachine.go:SaveSnapshot` calls `store.ExportSnapshot(false)` — audit entries are **dropped** after log compaction/recovery. Change to `ExportSnapshot(true)` or add config flag. Extend `internal/raft/statemachine_test.go` to assert audit count round-trips. Align `docs/storage/dragonboat.md` with behavior. | SaveSnapshot → RecoverFromSnapshot preserves audit entries. 3-node test: append audit, trigger snapshot, restart follower, audit list non-empty. |
| **W36-07** | Validate snapshot before `snapshot.import` | storage | S | W27-01 | **Hint:** `internal/raft/store.go:ImportSnapshot` calls `backup.Restore` directly; `backup.ValidateSnapshot` (`internal/backup/import.go:139`) is never invoked on Raft path. Call `ValidateSnapshot` in `SnapshotImporter` (`internal/raft/snapshot.go`) and `BackupService.Restore` before propose. Reject malformed parent CA refs, bad version. | `POST /sys/restore` with corrupt snapshot → `400` and state unchanged. Unit test on `Store.ImportSnapshot`. |
| **W36-08** | Consistent backup export (single Raft read) | storage | M | W27-01 | **Hint:** `backup.Export` (`internal/backup/export.go`) issues many separate `SyncRead`/list calls — torn snapshot across entity types. Add `OpExportSnapshot` read-only command in `internal/raft/commands.go` + `store.go` that serializes full state from state machine memory in one `Lookup`. `BackupService.Create` uses it when Raft enabled. | Export during concurrent writes: restored snapshot is self-consistent (all cross-refs valid). Test: write CA + secret, export mid-batch, validate graph. |
| **W36-09** | Align leader status with live Raft role | k8s | S | W26-02 | **Hint:** `internal/raft/leader.go:LeaderElector.IsLeader` uses 500ms poll cache; `internal/raft/events.go` updates metrics from Dragonboat `LeaderUpdated` — HTTP `/health` `leader` can disagree with `knxvault_raft_leader`. Expose `client.IsLeader()` / `LeaderID()` directly on `Dependencies.IsLeader()` when Raft enabled; or share atomic from `events.go`. | After forced leader step-down, `/health` `leader` and Prometheus gauge agree within one heartbeat RTT. Test in `internal/raft/leader_test.go`. |
| **W36-10** | Dragonboat repository adapter tests | ci | M | W26-01 | **Hint:** `internal/repository/dragonboat/repo.go` (~350 lines) has **zero** `*_test.go`. Add table-driven tests with mock `raftClient` interface (extract from concrete `*raft.Client` if needed): `Propose` error propagation, `DecodeResult` not-found, read-only op routing. | `go test ./internal/repository/dragonboat/...` passes; covers save/get/list for CA and secret repos. |
| **W36-11** | Raft leader failover integration test | ci | M | W28-01 | **Hint:** `test/integration/raft_test.go` only tests happy-path CA write + follower read; assertion passes on any non-empty JSON (including errors). Add `TestRaftLeaderFailover`: 3 nodes, write secret, stop leader NodeHost, wait for new leader, write again, read from all replicas. Decode `DecodeResult` / verify payload fields. | `make test-integration` includes failover test; fails if quorum lost >30s. Document timeout tuning in test comments. |
| **W36-12** | HTTP API integration tests with Raft enabled | ci | M | W26-01, W36-11 | **Hint:** `test/integration/api_test.go:32` sets `KNXVAULT_RAFT_ENABLED=false`. Add `api_raft_test.go`: single-node or 3-node Raft, run existing health/secrets/auth flows against Raft-backed deps. Mirror `newTestRouter` helper with `config.Load` + real `app.NewDependencies`. | PKI + KV round-trip passes with `RAFT_ENABLED=true`. CI runs both memory and Raft suites. |

### Tier C — Auth, tokens & RBAC polish

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| **W36-13** | Persist client tokens in Raft | auth | L | W25-02, W36-02 | **Hint:** `internal/auth/token.go:TokenStore` is in-memory only (`internal/app/deps.go:155`) — tokens lost on restart, not HA-safe. Add `token.save` / `token.get` / `token.revoke` Raft commands; optional TTL index for cleanup job. Issue flow proposes to Raft when enabled. | Issue token on node A, restart node A, token still authenticates on node B. Leader job expires TTL'd tokens. |
| **W36-14** | Wire `namespace` RBAC condition | auth | S | W13-01 | **Hint:** `internal/auth/evaluator.go:51–55` evaluates `namespace` condition but `internal/api/middleware/auth.go:40–42` never sets `RequestContext.Namespace`. Populate from `X-KNX-Namespace` header (optional, pre–W32) or K8s TokenReview SA namespace. | Policy with `namespace: prod` denies request without header; allows with `X-KNX-Namespace: prod`. Test in `evaluator_test.go` + middleware test. |
| **W36-15** | Fix `knxvault_active_leases` metric semantics | docs | S | W15-02 | **Hint:** `internal/app/jobs.go:114` sets `knxvault_active_leases` to cleanup **batch size**, not cluster-wide active lease count. Add `LeaseRepository.CountActive` (memory + dragonboat) or gauge from `List` length on leader tick. Update `docs/metrics.md` + `deployments/grafana/knxvault-overview.json`. | Metric reflects active leases; increments on creds generate, decrements on expire/revoke. |
| **W36-16** | Leader election loop health & job gating | k8s | S | W26-02 | **Hint:** If `LeaderElector.Run` fails silently (`internal/app/jobs.go:47–55`), background jobs stop with only a warn. Add metric `knxvault_leader_election_running`; escalate to error log + `/ready` 503 when loop exits. Ensure `JobRunner` no-ops when `!client.IsLeader()` as double-check. | Kill leader election goroutine in test → `/ready` not ready; jobs do not run on follower. |

### Tier D — Features documented but missing

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| **W36-17** | Master key rotation API | crypto | L | W3-02, W36-04 | **Hint:** LLD §7.2 `/sys/rotate` and CLI `knxvault sys rotate-master-key` documented but absent. Extend `internal/crypto/service.go` with keyring (versioned master keys); add `POST /sys/rotate-master-key` in `internal/api/router.go` + handler; re-encrypt DEKs in background job (`internal/app/jobs.go`). ADR-0003 follow-up. | Rotate accepts new base64 key; old secrets decryptable during transition; new writes use new key. CLI command works. |
| **W36-18** | Managed database credentials execution mode | crypto | L | W12-01 | **Hint:** `internal/domain/secrets/database_role_config.go:119` rejects `managed`; `admin_credentials_path` validated but never read. Implement: fetch KV at path via `SecretsEngine`, parse `connection_url`, execute `CreationStatements`/`RevocationStatements` with `database/sql` (or pgx/mysql drivers). Gate behind `execution_mode: managed`. Client mode remains default. See `docs/deploy/database-credentials.md`. | `POST /secrets/database/creds/:role` with `managed` role creates real DB user; revoke runs revocation SQL. Integration test with testcontainers MySQL. |
| **W36-19** | Return revocation SQL on lease revoke (client mode) | api | S | W12-01 | **Hint:** `internal/engine/secrets/database/engine.go:265–284` `RevokeLease` does not return `RevocationStatements` templates. Extend API response DTO (`internal/api/dto/database.go`) with `revocation_statements` for operators to run manually. | `PUT /secrets/database/revoke/:id` returns SQL strings when role defines them. |
| **W36-20** | Wire `EngineRegistry` at startup | api | S | W6-01 | **Hint:** `internal/engine/registry.go` exists, only used in `registry_test.go`. Register KVv2 + database engines in `internal/app/deps.go`; route future engines through registry. | Registry lists 2 engines; no behavior change for existing API. |
| **W36-21** | CLI parity for Day-2 operations | docs | M | W20-01 | **Hint:** CLI has `health`, `kv`, `pki`, `backup` only (`cmd/knxvault-cli/cmd/`). Add: `sys policies` CRUD, `sys roles`, `audit export`, `secrets database roles/creds`, `sys rotate-master-key` (after W36-17). Reuse `pkg/client/client.go`. Update `docs/cli/reference.md`. | Each documented CLI command in LLD §11 has working cobra subcommand. |
| **W36-22** | LLD / security-model doc reconciliation | docs | S | W36-01, W36-02, W36-04 | **Hint:** `docs/lld.md` still claims TokenReview (done), `/sys/rotate` (missing), mTLS (Phase 5). Audit `docs/architecture/security-model.md`, `docs/lld.md` §7 against code; add "implemented / planned / dev-only" labels. | No doc claims production feature that code lacks without "planned" tag. |

### Tier E — Deferred alongside Phase 5

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| **W36-23** | Dynamic Raft cluster membership | storage | XL | W28-02 | **Hint:** `internal/raft/nodehost.go` only `StartCluster` at boot with fixed `KNXVAULT_RAFT_INITIAL_MEMBERS`. No add/remove peer API. Research Dragonboat `NodeHost.RequestAddNode` / `RequestDeleteNode`; document rolling expand/shrink in `docs/operations/runbooks/scaling.md`. | Add 4th node via API; quorum maintained; documented rollback. |
| **W36-24** | Vault seal / unseal operational mode | security | L | W36-17 | **Hint:** LLD mentions `knxvault admin seal/unseal` — not implemented. Add sealed state in `internal/app/` blocking crypto + mutating API until unseal key provided. Distinct from envelope `crypto.Seal()`. | `POST /sys/seal` returns 503 on writes; unseal restores. CLI commands. |

> **Phase 5 dependency note:** **W37-01** supersedes **W34-01** (mTLS) in priority. **W32-**\* (multi-tenancy) should follow **W37-03** / **W36-14**. **W36-13** (token persistence) should precede **W34-02** (client cert issuance).

---

## Phase 5 — Ecosystem (planned)

High-level scope from LLD §9.4. Phase 3 is complete; Phase 4 hardening recommended first. Detailed design in [`docs/design/phase4-ecosystem.md`](design/phase4-ecosystem.md).

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| **W30-01** | Kubernetes Operator scaffold | k8s | L | W29 | kubebuilder project, CRD types for CA and policy resources. | CRDs apply cleanly; scaffold compiles. |
| **W30-02** | Operator reconciliation loop | k8s | L | W30-01 | Reconcile CRDs to KNXVault REST API with status conditions. | Create CA via CRD → visible in API; e2e test passes. |
| **W31-01** | OpenSSL engine abstraction | crypto | M | W3-03 | Pluggable engine interface in `internal/crypto/openssl/`. | Unit tests with mock engine. |
| **W31-02** | PKCS#11 HSM integration | crypto | L | W31-01 | HSM-backed CA key generation via OpenSSL engine. | Root CA created on SoftHSM; documented config. |
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

Deferred packaging and ecosystem work — not scheduled for Tier 0 / Phase 4–5 near-term delivery. Revisit after **W37** checklist items and **W36** hardening stabilize.

| Item | Area | Rationale |
|------|------|-----------|
| **Helm chart** | k8s | Active delivery tracked as **W37-08** (Tier 0). Hooks remain below. |
| **Cloud dynamic secrets (AWS IAM)** | crypto | Deferred as **LT-02**. Near-term: database dynamic engine + OIDC auth. |
| Helm hooks (pre-upgrade backup) | k8s | Depends on **W37-08** Helm chart. |
| Grafana dashboards bundled in chart | docs | Depends on **W37-08** Helm chart + W10 metrics. |

### Long-term backlog (detailed)

| ID | Title | Area | Effort | Depends on | Description | Acceptance criteria |
|----|-------|------|--------|------------|-------------|---------------------|
| **LT-01** | Terraform provider | docs | L | W37-08, Phase 5 stable | **Gap:** No IaC provider — operators must script REST or use `knxvault-cli`. **Hint:** New repo or `terraform-provider-knxvault/` using `hashicorp/terraform-plugin-framework`. Initial resources: `knxvault_kv_secret`, `knxvault_policy`, `knxvault_pki_root` (data source). Auth via provider `token` or `KNXVAULT_TOKEN` env. Publish `docs/integration/terraform.md`. Defer until Helm (**W37-08**) and core API auth (**W36-02**) are production-ready. | `terraform apply` creates KV secret and policy; `terraform destroy` removes. CI acceptance test against single-node dev server. |
| **LT-02** | Cloud dynamic secrets engine (AWS IAM scaffold) | crypto | XL | W37-02, W36-20, LT-01 optional | **Gap:** Only database dynamic engine (`internal/engine/secrets/database/`); no AWS/GCP/Azure on-demand creds. **Hint:** New `internal/engine/secrets/aws/` implementing `SecretEngine` — role config: `iam_role_arn`, `ttl`, `policy_document`. Use AWS SDK `sts:AssumeRole` with OIDC/web-identity from **W37-02** (preferred) or documented static IAM user (discouraged). Register in `EngineRegistry` (**W36-20**). API: `POST /secrets/aws/creds/:role`. Stub interfaces for GCP/Azure in follow-up. Defer until OIDC auth and engine registry are stable. | `POST /secrets/aws/creds/deploy` returns temporary access key + session token; lease revoke documented (STS limits). Integration test with LocalStack or sandbox account. |