<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# KNXVault full-codebase security, correctness, reliability, and K8s operational audit

| Field | Value |
|-------|-------|
| **Repo** | `/home/build01/repos/knxvault` |
| **HEAD** | `5242c30f86a1e390de48beafcb4cead4b479d78c` |
| **Scope** | Full product surface (not diff-only) |
| **Date** | 2026-07-16 |
| **Mode** | Read-only review |

---

## Summary

KNXVault is a substantial, well-layered secrets/PKI product with solid foundations: AES-256-GCM envelope crypto, Dragonboat Raft HA, path-aware RBAC, K8s/OIDC/AppRole auth, CSI/ESO/operator ecosystem, and generally careful OpenSSL CLI sandboxing. Ship risk for **production multi-tenant BFSI** is still **elevated** — not because the core crypto model is wrong, but because several operational security controls are incomplete or fail open: the mutating webhook serves plain HTTP, operational seal does not survive restart and still allows secret reads, AppRole and init state are not cluster-replicated, and K8s defaults disable rate limiting and omit Raft mTLS. Dominant risk areas are **K8s admission/TLS surface**, **HA auth consistency (AppRole/init/seal)**, and **API hardening (unauthenticated metrics/unseal, sealed-read path, unbounded limiters)**.

---

## Issues

### Issue 1 -- Severity: bug
- File: `/home/build01/repos/knxvault/cmd/knxvault-webhook/main.go:30`
- Description: The mutating admission webhook listens with `http.ListenAndServe` (plaintext HTTP) on `:9443`. Kubernetes admission webhooks require HTTPS; API server calls will fail TLS handshake. Combined with `failurePolicy: Fail` in `deployments/k8s/webhook/mutating-webhook.yaml:20`, enabling the webhook for labeled namespaces will block Pod CREATE/UPDATE.
- Suggestion: Serve TLS with a cert/key (or cert-manager/self-signed bootstrap), and document required webhook TLS Secret mounts. Prefer `http.Server` with `TLSConfig` and readiness checks that verify TLS is configured before registration.
- Status: open

### Issue 2 -- Severity: bug
- File: `/home/build01/repos/knxvault/internal/app/seal.go:16`
- Description: `NewSealState` leaves `sealed == false`. There is no boot path that starts sealed or restores seal state from durable storage. After any restart (including post-incident seal), the vault is operationally open as soon as the process has master key + env. Seal is therefore not an effective emergency control across restarts.
- Suggestion: Start sealed when `KNXVAULT_UNSEAL_KEY` is configured (or always when Raft is enabled); persist seal flag in Raft or require unseal on every process start before serving secured routes.
- Status: open

### Issue 3 -- Severity: bug
- File: `/home/build01/repos/knxvault/internal/api/middleware/seal.go:23`
- Description: `SealGuard` allows `GET`/`HEAD`/`OPTIONS` while sealed. Authenticated clients can still read KV secrets, CA material, leases, audit export (read paths), etc. during an emergency seal — only mutations are blocked. That contradicts typical Vault-like “sealed means no secret access” operator expectation.
- Suggestion: Block all non-sys/health and non-unseal routes when sealed (or at least all secret/PKI/data reads). Keep health/ready and `/sys/unseal` only.
- Status: open

### Issue 4 -- Severity: bug
- File: `/home/build01/repos/knxvault/internal/auth/approle.go:24`
- Description: AppRole credentials are explicitly **in-memory only** (“not Raft-replicated yet”). In a multi-node Raft deployment, AppRole registration on one node is invisible on others; cert-manager AppRole logins will fail/intermittently depending on which pod is hit; restart loses all AppRoles.
- Suggestion: Persist AppRole hashes via Raft repository (like tokens/policies); load on boot; never rely on process memory for HA auth methods used by cert-manager.
- Status: open

### Issue 5 -- Severity: bug
- File: `/home/build01/repos/knxvault/internal/sys/initstate.go:6`
- Description: Bootstrap/`POST /sys/init` initialization flag is process-local (`var initialized bool`). After restart every node believes it is uninitialized. A principal with `sys/init` write can call Init again and create additional root CAs (`handlers/sys.go:114`), producing CA sprawl and operational confusion. State is not coordinated across the Raft cluster.
- Suggestion: Store initialized flag (and optional root CA bootstrap marker) in Raft-backed sys state; refuse Init when any CA/sys marker already exists cluster-wide.
- Status: open

### Issue 6 -- Severity: bug
- File: `/home/build01/repos/knxvault/internal/crypto/pki/openssl_backend.go:252`
- Description: `subjectDN` concatenates `commonName` into OpenSSL `-subj` as `/CN=` + raw string without escaping. A CN containing `/` (e.g. `evil/O=Attacker/OU=x`) injects extra DN RDNs into the certificate subject. Any API/operator path that accepts CN (issue, root, intermediate, ACME CN) can produce unexpected certificate identity attributes.
- Suggestion: Reject CN characters outside a safe set, or escape `/` per OpenSSL DN rules; prefer native x509 APIs for subject construction when using native backend.
- Status: open

### Issue 7 -- Severity: bug
- File: `/home/build01/repos/knxvault/internal/api/middleware/mtls.go:65`
- Description: `certFingerprint` claims to return a SHA-256 fingerprint but actually returns the first 8 raw DER bytes as a Go `string` (and briefly references `cert.Signature` unused). This is not a fingerprint, is not hex-encoded, and is unsuitable for identity logging, audit correlation, or access decisions if used that way.
- Suggestion: `sha256.Sum256(cert.Raw)` and hex-encode; never use signature or truncated raw bytes as identity.
- Status: open

### Issue 8 -- Severity: bug
- File: `/home/build01/repos/knxvault/internal/eso/server.go:64`
- Description: ESO adapter `/fetch` and `/v1/fetch` have **no inbound authentication**. If the adapter can resolve a token via its ServiceAccount JWT (`resolveToken` falls through to SA login at line 132), any network peer that can reach the pod can request arbitrary KV paths (subject only to the SA role’s policies). Deployment exposes Service port 8080 without NetworkPolicy.
- Suggestion: Require mTLS or shared webhook secret from External Secrets; bind to localhost/ClusterIP with NetworkPolicy allow-list; never auto-login SA for unauthenticated callers — require ESO to present auth.
- Status: open

### Issue 9 -- Severity: bug
- File: `/home/build01/repos/knxvault/internal/app/app.go:92`
- Description: Main HTTP `Server` sets neither `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout` nor global body limits (only backup restore uses `MaxBytesReader`). Process is vulnerable to slowloris / connection exhaustion; large JSON bodies on many endpoints can amplify memory use under auth-throttled but still-expensive paths.
- Suggestion: Set conservative server timeouts (e.g. ReadHeaderTimeout 5–10s); apply request body size limits on mutating routes; consider middleware for max body size.
- Status: open

### Issue 10 -- Severity: bug
- File: `/home/build01/repos/knxvault/deployments/k8s/configmap.yaml:21`
- Description: Production StatefulSet ConfigMap ships `KNXVAULT_RATE_LIMIT_ENABLED: "false"`. Login throttles and general rate limiting depend on config; with rate limit off, unauthenticated login endpoints and authenticated APIs lack default DoS protection from the product’s own limiter.
- Suggestion: Enable rate limiting by default in production manifests; keep higher RPM only for load tests; ensure auth login throttle remains on even if global RL is tuned.
- Status: open

### Issue 11 -- Severity: bug
- File: `/home/build01/repos/knxvault/internal/api/router.go:403`
- Description: `POST /sys/unseal` is unauthenticated (by design) with only a per-router 10 RPM limiter. There is no lockout, no audit of failed unseal attempts in this path’s seal state machine, and constant-time compare helps but brute force of weak keys remains a remote attack if the API is network-reachable. NetworkPolicy allows ingress-nginx → 8200, so unseal is cluster-edge reachable if the Service is exposed.
- Suggestion: Multi-share unseal, progressive delay/lockout after failures, audit all attempts, and restrict unseal to an internal admin NetworkPolicy (not public ingress).
- Status: open

### Issue 12 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/raft/nodehost.go:38`
- Description: Raft mTLS is optional (`if cfg.MTLSCertFile != ""`). Default K8s ConfigMap does not set Raft mTLS paths, so inter-node Raft (port 63001) may carry replication traffic without mutual TLS inside the cluster. Compromise of any pod/network position can observe or inject Raft RPCs depending on Dragonboat transport assumptions.
- Suggestion: Require Raft mTLS whenever Raft is enabled in production ValidateSecurity; ship cert bootstrap in StatefulSet examples.
- Status: open

### Issue 13 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/api/router.go:38`
- Description: `GET /metrics` is registered outside the auth group and is unauthenticated. Metrics can leak operational topology (leader, raft TLS flags, build info, rate-limit counters, CSI rotations) useful for recon. NetworkPolicy does not restrict scrape sources beyond ingress-nginx + self for Raft.
- Suggestion: Protect metrics with NetworkPolicy (Prometheus NS only), or optional bearer auth / separate bind address.
- Status: open

### Issue 14 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/api/middleware/ratelimit.go:21`
- Description: Token-bucket `buckets map[string]*bucket` grows without eviction. Keys are ClientIP or TokenID. Long-running instances under scanning (many IPs) or high token churn can leak memory unbounded.
- Suggestion: Cap map size, LRU/TTL eviction of idle buckets, or use a library with bounded cardinality.
- Status: open

### Issue 15 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/auth/token.go:306`
- Description: `Authorize` / `AuthorizePath` / `SimulatePolicy` ignore `SyncRBAC` errors (`_ = s.rbacSync.SyncRBAC(ctx)`). If list/load of policies fails, authorization continues on potentially **stale** policy cache — revoked policies may still allow access until a successful sync.
- Suggestion: Fail closed on sync errors for sensitive operations, or serve last-known-good with explicit degraded metric and short max staleness deadline.
- Status: open

### Issue 16 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/engine/secrets/database/sql.go:42`
- Description: Managed DB roles execute fully rendered SQL strings via `db.ExecContext` with no statement allow-list. Custom `CreationStatements`/`RevocationStatements` (accepted in role config) run with admin credentials from KV. A principal with `secrets/database` write can run arbitrary SQL against the target DB (RCE-equivalent on DB plane: create superuser, exfiltrate data, etc.). Defaults are safer templates, but validation does not restrict custom SQL.
- Suggestion: Document as high-privilege; optional strict mode that only allows built-in templates; SQL parse/allow-list; separate capability e.g. `secrets/database/admin`.
- Status: open

### Issue 17 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/operator/controllers/issuer_backend.go:61`
- Description: Operator ACME issuance hardcodes `AcceptTOS: true` for every Issuer/ClusterIssuer. Operators never surface an explicit ToS acceptance field to cluster admins; legal/compliance acceptance is implicit whenever an ACME issuer CR is created.
- Suggestion: Require `spec.acme.acceptTOS: true` on the CR (default false) and refuse issue when unset; mirror cert-manager’s model.
- Status: open

### Issue 18 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/deployments/operator/rbac.yaml:26`
- Description: Operator ClusterRole grants full CRUD on cluster-wide `secrets` (get/list/watch/create/update/patch/delete). This is broader than least privilege for writing TLS secrets in certificate namespaces; any controller bug or CR abuse can read/overwrite arbitrary Secrets cluster-wide.
- Suggestion: Prefer namespaced RoleBindings per tenant namespace (sample exists: `rbac-namespaced-example.yaml`); if cluster-wide is required, limit to secrets with a label selector via ValidatingAdmission or controller-side allow-list of namespaces.
- Status: open

### Issue 19 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/deployments/k8s/networkpolicy.yaml:14`
- Description: Ingress NetworkPolicy only allows port 8200 from `ingress-nginx` and Raft from peer pods. Workloads using CSI/ESO/operator from other namespaces (or in-cluster clients not via ingress) cannot reach the vault API unless they go through ingress. Conversely, if operators open broader access later, there is no documented policy for CSI provider / knxvault-eso / operator SA namespaces.
- Suggestion: Explicitly document and add named ingress rules for knxvault-eso, operator, and CSI provider namespaces/pods; keep public ingress minimal (no unseal if possible).
- Status: open

### Issue 20 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/crypto/service.go:124`
- Description: `Seal`/`Open` generate and use DEKs but never call `memzero.Bytes` on plaintext DEKs after use. Package `internal/crypto/memzero` exists but is unused on the hot crypto path. Master key and DEKs remain in heap longer than necessary (no mlock either).
- Suggestion: Zero DEK buffers after encrypt/decrypt in `Seal`/`Open`/`DecryptDEK` paths; document mlock limitation for BFSI.
- Status: open

### Issue 21 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/auth/agent.go:48`
- Description: Agent delegate TTL has a default (15m) but **no maximum cap**. A parent with `auth/agent` write can issue non-renewable agent tokens with multi-year TTL if the client passes a large TTL, expanding blast radius of leaked agent tokens.
- Suggestion: Enforce max agent TTL (e.g. 1h) server-side independent of request.
- Status: open

### Issue 22 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/inject/csi/server.go:49`
- Description: CSI provider creates socket directory with `0o755` and does not set restrictive permissions on the unix socket after listen. On multi-tenant nodes, broader filesystem access to the provider socket increases risk of unauthorized Mount RPCs (still need SA token in mount request, but socket exposure is unnecessary).
- Suggestion: `0o750`/`0o700` dir; `chmod` socket to `0o660` with dedicated group matching CSI driver.
- Status: open

### Issue 23 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/api/middleware/exposure.go:73`
- Description: Exposure report HMAC signs only the body (no timestamp/nonce in MAC). Replay protection is a process-local `seen` map with 5-minute TTL; after TTL expiry the same signed body can be replayed; map is not cluster-wide.
- Suggestion: Include timestamp in signed payload (like request signing middleware), reject skew, and/or use nonce store in Raft.
- Status: open

### Issue 24 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/crypto/openssl/wrapper.go:144`
- Description: `validateArgs` blocks `-engine`/`-provider`/`-rand` and constrains `-config`, but does not generally restrict path arguments (`-in`, `-out`, `-key`, etc.). Today call sites pass workspace paths; if a future caller threads user input into args, OpenSSL could read/write arbitrary filesystem paths despite `cmd.Dir` temp sandbox (absolute paths bypass Dir).
- Suggestion: Require all path-like args to be under the per-exec workspace; refuse absolute paths outside workspace; fuzz more command shapes.
- Status: open

### Issue 25 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/acme/client.go:248`
- Description: `SkipTLSVerify` enables `InsecureSkipVerify` for ACME HTTP. Operator maps CR `SkipTLSVerify` through (`issuer_backend.go:62`). Easy to leave enabled against a “lab” ACME endpoint in production and MITM account keys/order traffic.
- Suggestion: Default false; log loud warning; block when Raft/production security profile is on (mirror `k8s_auth_insecure` gate).
- Status: open

### Issue 26 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/cmd/knxvault-eso/main.go:27`
- Description: ESO adapter also uses plain `ListenAndServe` with no TLS. Traffic between External Secrets webhook and knxvault-eso (tokens, secret values in responses) may be plaintext in-cluster.
- Suggestion: Optional TLS; at minimum NetworkPolicy + document that ESO ClusterSecretStore should use HTTPS when available.
- Status: open

### Issue 27 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/auth/token.go:161`
- Description: Root/bootstrap token is registered with a fixed 365-day expiry and is not forced to rotate. Long-lived root increases credential lifetime risk; K8s Secret example stores `KNXVAULT_ROOT_TOKEN` in etcd (normal for K8s, but amplifies root lifetime concern).
- Suggestion: Shorter default root TTL, mandatory rotation recipe, break-glass pattern with one-time root.
- Status: open

### Issue 28 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/api/middleware/auth.go:15`
- Description: If `AuthService` is nil, `Auth` and `RequirePermission` no-op (`c.Next()`). Router mostly gates route registration on non-nil auth, but the fail-open middleware pattern is dangerous if a future route group attaches Auth with a nil service or mis-wires deps under partial bootstrap (e.g. missing master key paths).
- Suggestion: Fail closed: abort 503/500 when auth middleware is installed without a service.
- Status: open

### Issue 29 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/deployments/csi/rbac.yaml:12`
- Description: CSI provider ClusterRole can `create` on `serviceaccounts/token` cluster-wide plus TokenReviews. Combined with hostPath socket, the DaemonSet is a high-value node identity broker. No PodSecurity/seccomp annotations on the DaemonSet beyond container securityContext.
- Suggestion: Scope token requests if API allows; add seccomp/AppArmor; ensure SPC always uses audience-bound tokens; document threat model.
- Status: open

### Issue 30 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/audit/forward.go:43`
- Description: Audit forwarder fires fire-and-forget goroutines with no queue, retry, or drop metrics. Under burst load, unbounded goroutines can exhaust resources; under SIEM outage, events are silently dropped (only local store remains if backend write succeeded).
- Suggestion: Bounded worker queue, retries with backoff, drop/failure counters, circuit breaker.
- Status: open

### Issue 31 -- Severity: nit
- File: `/home/build01/repos/knxvault/internal/engine/registry.go:29`
- Description: Duplicate engine registration `panic`s. Acceptable at boot if registration is static, but panics in library init paths complicate embedding/tests and can take down the process if configuration becomes dynamic later.
- Suggestion: Return error from `Register` and fail bootstrap with a logged error.
- Status: open

### Issue 32 -- Severity: nit
- File: `/home/build01/repos/knxvault/internal/api/middleware/seal.go:29`
- Description: Sealed responses use `AbortWithStatusJSON` while most API errors go through `ErrorHandler`/`common.KNXVaultError`, creating inconsistent error envelopes for clients/CLI.
- Suggestion: Route through the same error middleware for client consistency.
- Status: open

### Issue 33 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/webhook/mutate.go:57`
- Description: Injection mutates all containers with the same mount path from annotation; no validation that mount path is absolute/safe, no exclusion of init-only injection, and no check for conflicting volume names if pod already has `knxvault-secrets` non-CSI volume. FailurePolicy Fail makes annotation mistakes deny admission.
- Suggestion: Validate mount path; support opt-in container list annotation; use `failurePolicy: Ignore` for optional inject or dry-run docs.
- Status: open

### Issue 34 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/pkg/client/client.go:28`
- Description: SDK HTTP client has timeout but no TLS config hooks, no request signing helper wired to middleware signing, and default base URL is plaintext `http://localhost:8200`. Fine for CLI defaults; easy to misuse in production integrations without TLS verification knobs.
- Suggestion: Document TLS requirements; add optional `TLSClientConfig` / signing helpers matching server middleware.
- Status: open

### Issue 35 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/compat/vault/sign.go:1` (adapter surface via `internal/api/handlers/vaultcompat.go:187`)
- Description: Vault product profile mounts `POST /v1/:mount/sign/:role` with only coarse `pki` write permission — not path/mount-scoped capability. Any token with broad `pki` write can sign via any mount name alias, which may over-authorize multi-tenant PKI.
- Suggestion: Path-aware capability on mount/role (e.g. `pki/<mount>/sign/<role>`).
- Status: open

### Issue 36 -- Severity: suggestion
- File: `/home/build01/repos/knxvault/internal/config/security.go:10`
- Description: Production security gate forbids `k8s_auth_insecure` when Raft is enabled and requires unseal key, but does not require API TLS, Raft mTLS, rate limits, or non-empty JWT/TokenReviewer configuration for K8s auth. A Raft cluster can still run with HTTP API and insecure operational defaults if operators only satisfy the current checks.
- Suggestion: Expand `ValidateSecurity` “production profile” checklist (TLS, raft mTLS, rate limit, token reviewer required).
- Status: open

---

## Coverage by subsystem

| Subsystem | Risk | Notes |
|-----------|------|-------|
| Core vault (app/api/service/engine) | Medium–High | Strong routing/RBAC structure; seal semantics weak; HTTP timeouts missing; init state local |
| Auth (token/RBAC/OIDC/K8s/AppRole) | High | Path RBAC + deny-precedence good; AppRole not HA; SyncRBAC fail-open; agent TTL uncapped; root 365d |
| Raft / repository | Medium | Dragonboat wiring solid; mTLS optional; 10s propose timeout fixed; cleartext Raft by default in manifests |
| Crypto / OpenSSL / master key | Medium | Envelope AES-GCM sound; memzero underused; OpenSSL subject DN injection; path sandbox incomplete |
| Middleware (auth/seal/rate/signing) | High | Seal allows reads; rate limit map growth + disabled in deploy; metrics open; unseal exposed |
| Operator | Medium–High | Controllers structured; AcceptTOS forced; cluster Secrets power; ACME SkipTLSVerify passthrough |
| ACME multi-issuer | Medium | Real ACME client + Cloudflare DNS01; lab InsecureSkipVerify; webhook DNS unauthenticated to remote URL |
| Vault product profile | Medium | cert-manager shapes present; mount-level authz coarse; AppRole HA gap breaks profile in cluster |
| CSI | Medium | SA login + KV read correct shape; socket perms; cluster TokenRequest RBAC; integration test exists |
| ESO adapter | High | Unauthenticated fetch + SA auto-login is a critical cluster misconfig footgun |
| Webhook inject | High | Plain HTTP admission server is ship-blocking for K8s inject feature |
| Deploy (k8s/csi/cert-manager) | Medium–High | Good pod securityContext on StatefulSet; rate limit off; Raft mTLS absent; NP incomplete |
| CLI / pkg/client / doctor | Low–Medium | CLI redacts secrets by default (good); client TLS/signing ergonomics thin |
| Config / security validation | Medium | Good permission check on config file; production gate incomplete vs real threats |
| Audit | Low–Medium | Redaction present; forwarder reliability weak |
| Tests / gaps | — | Strong unit coverage on auth/crypto/operator pieces; gaps: webhook TLS e2e, AppRole HA, sealed-read policy, ESO authz, unseal lockout, OpenSSL DN injection |

---

## Test gaps on critical paths (high level)

1. **Webhook**: no test that server presents TLS; admission e2e under `failurePolicy: Fail`.
2. **Seal**: no test that sealed mode blocks KV GET; no restart-sealed persistence test.
3. **AppRole + Raft**: no multi-node registration/login consistency test.
4. **Init**: no cluster-wide single-init test after process restart.
5. **ESO**: no test that unauthenticated `/fetch` is rejected when SA is present.
6. **OpenSSL DN**: no adversarial CN with `/` RDN injection case.
7. **Rate limiter**: no cardinality/memory stress test.
8. **Raft mTLS**: optional path lightly validated; no negative test that production profile requires it.

---

## Positive observations (non-issue)

- Envelope encryption with per-secret DEKs and master key versioning is coherent (`internal/crypto`).
- K8s login requires TokenReview in Raft mode; insecure parse is gated (`validateKubernetesJWT`).
- Path-aware KV middleware and agent path prefix constraints are real (not route-only stubs).
- OpenSSL wrapper uses temp dir, minimal env, circuit breaker, and forbids some dangerous flags.
- StatefulSet runs non-root, drops caps, read-only root FS, seccomp RuntimeDefault.
- CLI redacts secret values unless `--show-secrets`.
- Audit detail redaction covers common credential keys.

---

## Issue counts

| Severity | Count |
|----------|------:|
| bug | 11 |
| suggestion | 23 |
| nit | 2 |
| **Total** | **36** |

---

## Verdict

**Conditional ship:** core crypto and vault API architecture are production-credible for a controlled POC, but do **not** enable the mutating webhook, ESO adapter, or multi-node AppRole/cert-manager profile in hostile multi-tenant clusters until Issues 1–5, 8, and deploy hardening (rate limit, Raft mTLS, seal semantics) are fixed.
