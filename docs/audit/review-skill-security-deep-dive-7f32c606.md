## Summary

Read-only security deep dive of knxvault at `/home/build01/repos/knxvault`, focused on auth, middleware, seal/unseal, crypto/OpenSSL, operator secrets/RBAC/ACME SSRF, Raft encrypt-before-replicate claims, and deployment YAML.

**Strengths (evidence-based):**
- KV/PKI/DB/SSH engines call `crypto.Seal` before repository/Raft writes (`data_enc`/`dek_enc` / `private_key_enc`); ADR-0004/0005 match implementation.
- K8s login fail-closed when Raft is on without TokenReview; SA bindings required; AppRole uses SHA-256 + `subtle.ConstantTimeCompare`.
- Unseal uses constant-time key compare; unseal≠master enforced when Raft enabled; unauthenticated unseal is rate-limited.
- OpenSSL wrapper: temp `0700` workdirs, minimal env (`OPENSSL_CONF=/dev/null`), timeout, circuit breaker, forbidden `-engine`/`-provider`/`-rand`.
- Secrets path `..` rejected; database role config rejects credential-like keys; audit redaction present.

**Highest-impact residual risks:** ACME/DNS webhook SSRF from operator, operator ClusterRole cluster-wide Secrets CRUD, production StatefulSet missing TokenReview RBAC, AppRole registry not Raft-replicated, operational seal still allows authenticated secret **reads**, OpenSSL `-subj` DN injection via CN, production ConfigMap leaves global rate limit off.

No code was modified.

## Issues

### Issue 1 -- Severity: bug
- File: /home/build01/repos/knxvault/internal/acme/webhook.go:20-47
- Description: DNS-01 `WebhookDNS01` POSTs to a CR-supplied URL with a default `http.Client` (30s timeout), no scheme/host allowlist, no private/link-local/metadata deny list, and redirects followed. Operator wires CR `spec.acme.dns01.webhookURL` straight into this path (`issuer_backend.go:65-67`, `issuer_factory.go:33-37`). Any principal who can create Issuer/ClusterIssuer can force the operator pod to request internal endpoints (cloud metadata, kube API, link-local services). Same SSRF class for attacker-controlled ACME directory: `Client.ProbeDirectory` / `httpClient` use `DirectoryURL` / `spec.acme.server` with optional `SkipTLSVerify: true` (`client.go:89-114`, `245-250`; `issuer_backend.go:58-62`).
- Suggestion: Validate webhook and ACME directory URLs (prefer https; explicit host allowlist or deny RFC1918/link-local/metadata); disable redirects; cap response size; gate `SkipTLSVerify` to non-production only (env kill-switch). Restrict who can create ClusterIssuers.
- Status: open

### Issue 2 -- Severity: bug
- File: /home/build01/repos/knxvault/deployments/operator/rbac.yaml:26-28
- Description: Default operator `ClusterRole` grants cluster-wide `secrets` verbs `get,list,watch,create,update,patch,delete`. Compromise of the operator SA (or a path that tricks reconcile into overwriting an arbitrary Secret name/namespace) becomes full cluster secret exfiltration/destruction. A namespaced least-privilege example exists (`rbac-namespaced-example.yaml`) but is not the default install path. Controllers write TLS private keys into Secrets (`secretutil/tls.go:19-47`; certificate controller `SetControllerReference` + Create/Update).
- Suggestion: Ship default manifests without cluster-wide Secret CRUD; use namespaced Roles per app namespace (or ResourceNames + labels); document multi-tenant install as the production default; consider ValidatingAdmissionWebhook for Secret name/namespace constraints.
- Status: open

### Issue 3 -- Severity: bug
- File: /home/build01/repos/knxvault/deployments/k8s/role.yaml:1-11
- Description: Production StatefulSet SA (`knxvault`) only has `coordination.k8s.io/leases` for leader election. There is **no** ClusterRole for `authentication.k8s.io/tokenreviews` create on the server SA (CSI has TokenReview RBAC in `deployments/csi/rbac.yaml:15-17`, server does not). In-cluster `NewInClusterTokenReviewer` still constructs a client (`deps.go:298-311`), so TokenReviewer is non-nil; reviews fail at API with Forbidden → k8s login returns unauthorized (`token.go:521-524`). Docs claim TokenReview is automatic in production (`docs/architecture/security-model.md`). Result: Kubernetes auth is broken in the default HA deploy (fail-closed, but production-unsafe / ops may “fix” with insecure flags).
- Suggestion: Add ClusterRole/Binding for TokenReview (and only that) to the knxvault server SA in `deployments/k8s/`; document in install recipe; CI-check manifests vs in-cluster auth requirements.
- Status: open

### Issue 4 -- Severity: bug
- File: /home/build01/repos/knxvault/internal/auth/approle.go:24-58
- Description: AppRole store is explicitly “not Raft-replicated yet” (in-memory map). `Register`/`Authenticate` never hit repository/Raft. Docs and security model mark AppRole as production for cert-manager (`security-model.md` AppRole row) while admitting non-replication. After restart or failover to another node, `POST /v1/auth/approle/login` fails until re-registration; secret_ids cannot be recovered (hashes only). This is an auth availability / HA integrity bug that can push operators toward long-lived root tokens.
- Suggestion: Persist AppRole definitions (role_id, secret_hash, subject, policies) via Raft ops; rehydrate on boot; or hard-fail AppRole when Raft multi-node is enabled until implemented.
- Status: open

### Issue 5 -- Severity: bug
- File: /home/build01/repos/knxvault/internal/api/middleware/seal.go:16-33
- Description: `SealGuard` blocks only non-safe methods (POST/PUT/PATCH/DELETE). Authenticated GET/HEAD still proceed when sealed. Master key remains loaded in process memory (`deps` crypto service); KV/PKI reads continue to decrypt. Operational seal therefore does **not** stop secret exfiltration during an incident response seal—only mutations. Tests document write-block-only behavior (`seal_test.go:14-39`). Unauthenticated unseal is intentional (`router.go:397-404`) with 10 rpm limiter.
- Suggestion: For incident seal, block secret-bearing reads (or all routes except health/unseal/status) unless an explicit `seal_mode=writes_only` config is set; document clearly that seal ≠ crypto wipe; optional: zero/unload DEK capability only after multi-share unseal redesign.
- Status: open

### Issue 6 -- Severity: bug
- File: /home/build01/repos/knxvault/internal/crypto/pki/openssl_backend.go:252-254
- Description: `subjectDN` builds `"/CN=" + commonName + "/O=KNXVault"` without escaping. OpenSSL `-subj` treats `/` as RDNs. User-controlled CommonName from PKI issue/root/intermediate APIs can inject extra DN attributes (e.g. `evil/CN=trusted.example.com/O=…`), producing certificates with attacker-chosen subject fields while operators may trust CN alone. Args are passed via `exec.Command` (no shell), so classic shell injection is not present; DN injection is. Wrapper forbids `-engine`/`-provider` but does **not** forbid absolute `-config` paths that override env (`wrapper.go:144-157`), weakening sandbox if any caller ever supplies it.
- Suggestion: Reject CN/SAN containing `/`, control chars, and OpenSSL metacharacters; use native x509 templates (already available as `native` backend) for subject construction; expand `validateArgs` to deny absolute paths outside workspace for all path-taking flags; never pass user strings as free-form argv.
- Status: open

### Issue 7 -- Severity: bug
- File: /home/build01/repos/knxvault/internal/auth/lockout.go:8-80
- Description: Login lockout is process-local (maps under mutex), keyed primarily by source IP (`LoginLockoutKey` → `method:ip`, `login_context.go:5-10`). Multi-node Raft: attacker can rotate targets across pods to avoid lockout; reverse proxy misconfig allows `ClientIP()` spoofing via X-Forwarded-For (Gin default when trusted proxies not locked down—no `SetTrustedProxies` in `app.go` server setup). Shared NAT egress can lock legitimate users (DoS). No Raft/shared store for lockout state.
- Suggestion: Set trusted proxies explicitly; prefer identity-based lockout keys after partial auth (role_id hash, OIDC sub) in addition to IP; replicate lockout or use external limiter; document NAT tradeoffs.
- Status: open

### Issue 8 -- Severity: bug
- File: /home/build01/repos/knxvault/internal/operator/controllers/issuer_backend.go:58-62
- Description: Operator hardcodes `AcceptTOS: true` for every ACME issue, ignoring explicit consent. Combined with SSRF Issue 1 and arbitrary `Server` URL, the operator always agrees to whatever CA’s ToS the directory presents. CRD documents account key Secret ref but does not load/store it (new ECDSA account key every issue—`client.go:123-130`), increasing ACME rate-limit burn and account chaos under attack/retry loops.
- Suggestion: Require `spec.acme.acceptTOS`; implement account key Secret load/store; refuse Ready when unset.
- Status: open

### Issue 9 -- Severity: suggestion
- File: /home/build01/repos/knxvault/deployments/k8s/configmap.yaml:21-22
- Description: Production ConfigMap sets `KNXVAULT_RATE_LIMIT_ENABLED: "false"`. Global secured-route rate limiting is off by default in the HA template. Login throttle may still apply when deps wire auth limiters, but general API abuse (token brute-force on other surfaces, expensive PKI/OpenSSL ops) is not capped. NetworkPolicy allows ingress only from `ingress-nginx` + peer Raft (`networkpolicy.yaml`), which helps but does not replace app-layer limits behind a compromised ingress path.
- Suggestion: Default `true` for production manifests; keep RPM tunable; ensure AuthLogin + TokenCreate limiters always enabled when Raft is on.
- Status: open

### Issue 10 -- Severity: suggestion
- File: /home/build01/repos/knxvault/internal/auth/token.go:160-168
- Description: Bootstrap root token is registered with **365-day** expiry and full `admin` policy (`deps.go:265-268` → `[]string{"admin"}`). Default `admin` policy is `Resources: ["*"], Actions: ["*"]` (`rbac.go:19`). Root lives in K8s Secret stringData (`deployments/k8s/secret.yaml:17`). Long-lived superuser + cluster Secret access is a high-value persistent credential if the Secret or process env is leaked.
- Suggestion: Short default TTL for root; force one-time bootstrap then revoke; support root disable; prefer short-lived admin tokens from K8s SA; externalize root via sealed-secrets/ESO with rotation runbook.
- Status: open

### Issue 11 -- Severity: suggestion
- File: /home/build01/repos/knxvault/internal/api/middleware/auth.go:13-17
- Description: `Auth`, `RequirePermission`, `RequirePathCapability`, and `RequireKVAccess` all no-op (`c.Next()`) when `svc == nil`. Router currently only mounts secret/PKI routes when `AuthService != nil`, so production wiring is OK, but this is fail-open middleware—any future miswire (tests, alternate binary, partial deps) silently disables authz.
- Suggestion: Fail closed: if middleware is attached and svc is nil, abort 500/401; add startup assertion that secured groups never register without auth.
- Status: open

### Issue 12 -- Severity: suggestion
- File: /home/build01/repos/knxvault/docs/adr/0005-cleartext-metadata-in-raft.md:14-33
- Description: Intentional cleartext in Raft WAL/snapshots includes secret **paths**, RBAC policies/roles (including SA bindings and OIDC config), audit resources, PKI metadata. Encrypt-before-replicate is correctly implemented for payloads/private keys (verified: `kvv2.go:69-71`, PKI `engine.go:141-154`, DB/SSH seal paths). Attackers with PVC/backup access map infrastructure and policy structure without the master key. Not a claim violation, but residual confidentiality risk operators may underweight.
- Suggestion: Keep ADR; enforce volume encryption + NetworkPolicy; optional path-prefix isolation via multi-tenant clusters; ensure backups of Raft data have same classification as path inventory.
- Status: open

### Issue 13 -- Severity: suggestion
- File: /home/build01/repos/knxvault/internal/app/deps.go:483-489
- Description: `resolveUnsealKey`: if `KNXVAULT_UNSEAL_KEY` is unset/non-base64, unseal key **falls back to the master key**. Raft path requires unseal set and ≠ master (`deps.go:184-189`), but non-Raft / misconfig paths collapse custody of operational seal and encryption root into one secret. Seal then does not provide a second control plane key.
- Suggestion: Never fall back to master; require explicit unseal when seal feature is enabled; refuse start if equal.
- Status: open

### Issue 14 -- Severity: suggestion
- File: /home/build01/repos/knxvault/internal/api/router.go:38
- Description: `GET /metrics` is unauthenticated. Security model recommends NetworkPolicy restriction; sample NetworkPolicy does not carve metrics separately and only allows ingress-nginx → 8200, which may still expose metrics via the same ingress if routed. Metrics can leak auth throttle counts, build info, and operational signals useful for attackers.
- Suggestion: Separate metrics listener/port; NetworkPolicy default-deny + scrape allowlist; optional bearer for metrics.
- Status: open

### Issue 15 -- Severity: nit
- File: /home/build01/repos/knxvault/internal/api/middleware/mtls.go:65-77
- Description: `certFingerprint` does not compute SHA-256 of `Raw`; it copies up to 8 raw certificate bytes and returns them as a Go string—unsuitable as a stable cryptographic fingerprint if used for identity binding.
- Suggestion: Use `sha256.Sum256(cert.Raw)` hex; do not use truncated raw DER as identity.
- Status: open

### Issue 16 -- Severity: nit
- File: /home/build01/repos/knxvault/internal/crypto/openssl/wrapper.go:59-65
- Description: Forbidden flag set is narrow (`-engine`, `-provider`, `-provider-path`, `-rand`). Other dangerous/less-sandboxed options are not blocked (e.g. `-config` with absolute path is explicitly allowed when absolute and without `..`). Current PKI backend builds argv itself (lower risk), but the sandbox claim is incomplete for future callers of `SafeExec`.
- Suggestion: Allowlist openssl subcommands and flags; force all file operands under the temp workspace; reject absolute paths outside tmpDir.
- Status: open

## Positive controls (for balance)

| Area | Evidence |
|------|----------|
| Envelope encrypt-before-Raft | `KVV2Engine.Put` → `crypto.Seal` → `DataEnc`/`DEKEnc`; PKI CA keys sealed; ADR-0004 |
| K8s auth binding | Empty SA bindings → forbidden; TokenReview preferred; insecure+Raft rejected |
| Token storage | Only SHA-256 of token stored; opaque `knxv_` tokens |
| AppRole secret compare | Constant-time; secret hashed at rest in memory store |
| Unseal compare | `subtle.ConstantTimeCompare`; rate limit on `/sys/unseal` |
| DB role secrets | `ValidateDatabaseRoleConfig` rejects password/connection_url etc. |
| Master key file load | Absolute path, no `..`, `OpenRoot` + regular file check |
| Audit | `SanitizeDetails` redacts sensitive keys / embedded URLs |
| Container | Non-root 65532, drop ALL caps, read-only rootfs in StatefulSet |

## Scope notes

- No exploit development or runtime attacks performed.
- Did not re-audit non-focus areas (full backup/restore, CSI provider, ESO adapter) beyond where they touch TokenReview/RBAC.
- Prior audit notes on ACME HTTP-01 listener/shared presenter (`docs/audit/review-skill-main-vs-origin-2026-07-16.md`) remain operational bugs; SSRF/RBAC findings above are security-critical even when ACME issue is incomplete.
