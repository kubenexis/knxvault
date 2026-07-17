<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security Model

Threat assumptions, cryptographic controls, and operational security guidance for KNXVault.

## Posture assessment and roadmap

Honest grades, known gaps (set-and-forget Medium, custody vs HSM, DIY footguns), and the program to close them:

- [Security posture assessment](security-posture-assessment.md) — baseline  
- [Production security posture design](../design/production-security-posture.md) — M-PRODSEC-1 / M-CUSTODY-1  
- Backlog **W62-***, **W63-***, optional **W64-*** in [`docs/backlog.md`](../backlog.md)

**Shipped (A1):** set `KNXVAULT_SECURITY_PROFILE=production` (or `security.profile: production`) for fail-closed startup validation — requires audit signing key, metrics bearer, TLS or `TLS_TERMINATION=ingress`, rejects lab auth/Raft insecure flags, caps root TTL at 4h, requires multi-node Raft mTLS, hardens Valkey URL shape, and rejects plain `ldap://` / LDAP insecure skip. See `config/knxvault.production.yaml` and [configuration](../installation/configuration.md).

**W74 audit remediations (2026-07-17):** LDAP server-side only; wrap/identity sealed persistence; lease TokenID cascade + bulk selector; transit race/AAD/HMAC docs; webhook dial-time SSRF client. Report: [security-remediation-w74-2026-07-17.md](../audit/security-remediation-w74-2026-07-17.md).

## Threat model

| Threat | Impact | Mitigations |
|--------|--------|-------------|
| Master key compromise | All secrets and CA keys recoverable | K8s Secret sealing, short exposure window, backup key custody, `POST /sys/rotate-master-key` |
| Raft quorum loss | Write unavailability | 3-node cluster, PVC backups, documented failover runbook |
| Token theft | Unauthorized API access | Short TTL, RBAC least privilege, rate limiting, optional request signing |
| PKI key material exposure | Host/memory compromise | In-process issuance only; CA keys envelope-encrypted at rest; non-root container |
| Audit tampering | Compliance failure | Hash-chained log, HMAC export signatures, Raft replication |
| Network eavesdropping | Credential exposure | TLS at ingress (operator responsibility); server TLS (**W37-01**, shipped) and Raft peer mTLS (**W38-14**, shipped); broader route mTLS → Phase 5 **W34-01** |

## Cryptography

**Post-quantum:** KNXVault is **not PQ-ready**. At-rest envelopes use **AES-256-GCM** (relatively durable under Grover if keys are strong). **PKI (RSA) and classical TLS are not post-quantum.** Dual-stack generations (g1 classical default, g2+ opt-in), roadmap, and **PQ backlog** live under [`docs/pq/`](../pq/README.md). Do not claim “post-quantum ready” until those gates complete.

### Master key

- 32-byte random key, base64-encoded
- Loaded from `KNXVAULT_MASTER_KEY` or `KNXVAULT_MASTER_KEY_FILE`
- Never logged or returned via API
- See [ADR-0003](../adr/0003-envelope-encryption.md)

### Encrypt before replication

Secret and key material is **never written to Raft in plaintext**. Engines seal data before calling repositories; Raft only ever proposes already-encrypted domain objects.

```
PutSecret
    │
Serialize (JSON)
    │
Encrypt — AES-256-GCM envelope (per-object DEK, master-wrapped DEK)
    │
Replicate via Dragonboat (Propose)
    │
Persist — Pebble WAL + snapshots contain ciphertext
```

An attacker with Raft disk access sees base64-encoded `data_enc` and `dek_enc` fields — not recoverable without `KNXVAULT_MASTER_KEY`. See [ADR-0004](../adr/0004-encrypt-before-replication.md).

### Envelope encryption

1. Generate per-object DEK (AES-256)
2. Encrypt payload with DEK (AES-256-GCM)
3. Wrap DEK with master key
4. Store `DataEnc` + `DEKEnc` in Raft state (only after steps 1–3)

CA private keys and secret payloads use the same pattern.

For implementation detail (nonce layout, KeyRing rotation, master key loading, wire formats), see [Envelope encryption](envelope-encryption.md).

### PKI operations

X.509 operations use **in-process** Go `crypto/x509` only (`internal/crypto/x509native`). There is no OpenSSL CLI subprocess. Historical ADR: [ADR-0002](../adr/0002-openssl-cli-crypto-backend.md) (removed).

## Authentication

| Method | Use case | Configuration | Status |
|--------|----------|---------------|--------|
| Bootstrap root token | Initial admin | `KNXVAULT_ROOT_TOKEN` | Production |
| Opaque client tokens | Automation, CLI | `POST /auth/token/create`, renew, revoke | Production |
| Kubernetes ServiceAccount | In-cluster workloads / operator / CSI | TokenReview; `POST /auth/kubernetes` or `/v1/auth/kubernetes/login` | **Production** |
| AppRole | cert-manager / external Vault clients | `POST /sys/auth/approle` then `/v1/auth/approle/login` | **Production** (file + Raft-replicated encrypted blob at `sys/internal/approles`) |
| Client certificate (mTLS) | Mutual-TLS API clients | `POST /auth/cert` with peer cert; CN/DNS SAN → role policies | **Production** (W34-02 / W53; chain trust is TLS handshake) |
| OIDC | Human / federated IdP | `POST /auth/oidc/:role` | Production |
| Kubernetes JWT (HS256) | Local dev only | `KNXVAULT_JWT_SECRET` | Dev-only |
| K8s login bypass | Local dev only | `KNXVAULT_K8S_AUTH_INSECURE=true` | Dev-only (never with Raft) |

**Vault product profile tokens:** cert-manager and Vault clients may send `X-Vault-Token` (accepted by auth middleware alongside `Authorization: Bearer` and `X-KNXVault-Token`).

### Kubernetes authentication (production)

When KNXVault runs in a Kubernetes cluster, `POST /auth/kubernetes` validates the caller's ServiceAccount JWT via the **`authentication.k8s.io/v1` TokenReview** API (`internal/infra/k8s/tokenreview.go`). The API server confirms token authenticity; KNXVault maps the reviewed SA to a vault role.

**Fail-closed behavior:** If Raft is enabled (production mode) and neither TokenReview nor an explicit dev bypass is configured, login is rejected with `401`. Arbitrary JWT strings cannot mint client tokens.

**Role bindings:** Roles may restrict login to specific service accounts via `bound_service_account_names` and `bound_service_account_namespaces`. A successful TokenReview with a non-matching SA returns `403`.

**Auth method enforcement:** Roles with `auth_method: "oidc"` reject Kubernetes login; roles with `auth_method: "kubernetes"` reject OIDC login. K8s login resolves `policy_groups` the same way as OIDC.

**OIDC JWT requirements:** OIDC login rejects JWTs without an `exp` claim. Renewals cannot extend OIDC tokens beyond the role `max_ttl_seconds` cap stored as `max_expires_at`. JWKS fetches use a 10s HTTP timeout and refresh once on unknown `kid` during key rotation. Machine identity revocation checks fail closed when the NHI backend is unavailable.

**Login lockout (W43-04 / W53):** Failed `/auth/kubernetes`, `/auth/oidc/*`, `/auth/token`, `/auth/cert`, and AppRole login attempts are tracked with identity-preferring keys (`LoginLockoutKey`). After `KNXVAULT_AUTH_LOCKOUT_THRESHOLD` failures within the window, further logins are rejected until TTL expiry, successful login, or admin clear. When `KNXVAULT_VALKEY_CACHE_URL` is set, lockout counters are **cluster-shared** via Valkey (`SharedLockoutTracker`); otherwise process-local. Lockout emits `auth.lockout` audit events; admin clear emits `auth.lockout.clear`. Break-glass clear: `DELETE /sys/auth/lockout` with `{"auth_method":"kubernetes","source_ip":"10.0.0.1"}` (requires `sys/auth` sudo).

**ABAC attributes (W44-02):** Send `X-KNX-Environment` and optional `X-KNX-Cluster` on API requests when policies use `environment` or `cluster` conditions. Gin route template and URL path are available as `request_path` in policy evaluation.

**Dev-only paths:** `KNXVAULT_JWT_SECRET` enables HS256 validation for local testing. `KNXVAULT_K8S_AUTH_INSECURE=true` parses JWT structure without signature verification when Raft is disabled — still requires a `system:serviceaccount:…` subject for SA binding checks; never enable in production.

**HA client tokens:** When Raft is enabled, opaque client tokens (root, `POST /auth/token/create`, K8s login) are replicated via `token.save` / `token.get` / `token.revoke` Raft commands. Tokens survive node restarts and authenticate on any cluster member.

**RBAC cluster sync:** Each node reloads persisted policies from Raft before `Authorize` when the policy set hash changes, so policy writes on the leader are visible on followers without restart. `SyncRBAC` holds an exclusive lock across list-and-reload to avoid overwriting concurrent policy updates with a stale snapshot.

Tokens carry a TTL (`KNXVAULT_TOKEN_TTL`, default 24h). The bootstrap **root token** defaults to **`KNXVAULT_ROOT_TOKEN_TTL=72h`** (W50-26; was 365d) and must be rotated to scoped admin tokens after bootstrap policies are established.

### Recent hardening (2026-07-16 audits)

**10-cycle bugfix** ([report](../audit/formal-10cycle-bugfix-coverage-2026-07-16.md)):

- Metrics bearer compare is length-safe; optional `KNXVAULT_METRICS_BEARER_TOKEN`.
- `RequirePathCapability` fails closed when auth is nil.
- Seal middleware allows only exact `/sys/unseal` (no path-suffix bypass).
- KV `list` query `prefix` rejects `..` path traversal.
- ACME solvers nil-safe; public LE rejects `skipTLSVerify`.

**5-cycle security auditor** ([report](../audit/formal-5cycle-security-auditor-2026-07-16.md)):

- **CSR sign enforces PKI role `AllowedDomains` / MaxTTL** (same as issue path).
- `RequireKVAccess` fails closed when auth is nil.
- ACME directory URL static SSRF checks (private IP / metadata hosts).
- ESO fetch path rejects `..` and absolute paths.
- Client cert fingerprint is real SHA-256 hex of leaf DER.
- Agent path prefixes reject `..`; audit redact covers `jwt` / `client_token` / keys.

**3-cycle technical review** ([report](../audit/formal-3cycle-tech-review-2026-07-16.md)):

- `ParseTTL` rejects non-positive / absurd durations; admin tokens clamp to 30d max.
- Backup create validates JSON; HTTP-01 tokens and webhook mount paths reject path tricks.
- Login lockout map bounded under credential stuffing.

**W52 full-audit remediation** ([report](../audit/formal-security-remediation-w52-2026-07-16.md)):

- Seal marker file cannot unseal without the unseal key (restart always starts sealed when key configured).
- PKI roles default-deny without `allowed_domains`; IP SANs need `"*"`; SignCSR requires real roles.
- Vault-compat sign requires path-scoped policies (`pki/sign/*` / `pki/*`), not bare `pki` write.
- Rate limits on by default; CSI/SDK require HTTPS (loopback http allowed); OCSP rate-limited.
- Agent delegation requires explicit policy list; insecure K8s auth needs lab flag.

**W53 residual features** ([report](../audit/formal-w53-residual-features-2026-07-16.md)):

- **Multi-tenant non-KV isolation:** with `KNXVAULT_TENANT_MODE=true`, DB/SSH/PKI role and CA names are scoped by tenant namespace (same model as KV paths).
- **Shamir multi-share unseal:** `KNXVAULT_UNSEAL_THRESHOLD` + `POST /sys/unseal` with `share` (base64); admin split via `POST /sys/generate-unseal-shares` (unsealed only) or offline `scripts/shamir-split`. **Lab E2E:** start sealed → t-of-n shares → data plane (**53/53** — [lab-full-e2e.md](../engineering/lab-full-e2e.md), [e2e-and-lab-tests.md](../engineering/e2e-and-lab-tests.md)).
- **AppRole Raft replication:** encrypted `sys/internal/approles` blob via SecretRepository (Dragonboat when Raft on); file persist still used when data dir set.
- **Client-cert API login:** `POST /auth/cert` maps mTLS peer CN/DNS SAN → role policies → opaque token.
- **Cluster-shared rate limit / lockout:** Valkey-backed counters when `KNXVAULT_VALKEY_CACHE_URL` is set (best-effort get/set, not atomic INCR).

### Trusted proxies and login lockout (W50-18)

Gin does **not** trust `X-Forwarded-For` unless you set **`KNXVAULT_TRUSTED_PROXIES`** to load-balancer CIDRs. Without it, lockout keys use the TCP peer address. When identity is known (SA subject / OIDC sub), lockout prefers the identity key over IP so shared NATs cannot bypass per-principal lockouts as easily.

### Raft mTLS (W50-20)

Multi-node Raft requires `KNXVAULT_RAFT_MTLS_CERT` / `KEY` / `CA`. Lab-only: `KNXVAULT_RAFT_ALLOW_INSECURE=true`.

## Authorization (RBAC)

Policies grant capabilities on path prefixes:

| Capability | Typical paths |
|------------|---------------|
| `read` | `secrets/kv/*`, `pki/ca/*` |
| `write` | `secrets/kv/*`, `pki/*` |
| `delete` | `secrets/kv/*` |
| `sudo` | `sys/*`, `audit/*` |

Conditions restrict by source IP, time window, K8s namespace, path prefix, or `agent_id`. Evaluated in `internal/auth/evaluator.go` before handler execution.

**Namespace condition:** Set `RequestContext.Namespace` from the `X-KNX-Namespace` request header or, for Kubernetes ServiceAccount tokens, from the `system:serviceaccount:{ns}:{name}` subject. ServiceAccount tokens **cannot** spoof another namespace via `X-KNX-Namespace`; a mismatched header returns `403`. Non-SA principals may still supply the header for ABAC evaluation.

**AI agent delegation (W37-04):** Parent principals call `POST /auth/agent/delegate` to mint a non-renewable 15-minute token scoped by `path_prefix` (`agent/{id}/*` under `secrets/kv/`) and `allowed_actions`. Client-supplied `policies` must be a subset of the parent's resolved policies; omit the field to inherit parent policies. Delegation is audited (`auth.agent.delegate`) with `parent_identity_id` → `agent_id` linkage on `MachineIdentity`.

**KV path normalization:** Secret API paths containing `..` are rejected before authorization. Invalid `?version=` on DELETE returns `400` instead of `500`. Read-through cache entries are tagged with a per-path generation counter so concurrent writes cannot repopulate stale values.

**Exposure reports:** `POST /sys/exposure/report` rejects duplicate HMAC signatures within a 5-minute replay window. Bulk lease revocation returns partial results when mid-batch failures occur after earlier revocations succeeded.

**CSI mount audit (W39-02):** The CSI provider authenticates each mount with the workload ServiceAccount JWT (TokenReview on the API). After a successful read, the provider calls `POST /inject/csi/mount-audit` with the short-lived session token; audit action `csi.mount` records role, namespace, service account, and paths.

Default bootstrap policy `admin` grants full access. Production clusters should define scoped policies per workload.

**Policy engine guide:** See [`policy-engine.md`](policy-engine.md) for path-aware ACLs, capabilities, glob patterns, deny precedence, simulation, and HCL import (W41-01–10).

## Audit

Every sensitive operation appends to the hash-chained audit log:

```
hash(n) = SHA-256(prev_hash || entry_payload)
```

Export via `GET /audit/export` includes the chain head and optional HMAC signature (`KNXVAULT_AUDIT_SIGNING_KEY`). Each entry may carry a per-entry signature when a signing key is configured. Verify with `POST /audit/verify`.

Optional SIEM forwarding: set `KNXVAULT_AUDIT_FORWARD_URL` to POST each entry asynchronously to an HTTP sink. See [audit forwarding](../observability/audit-forwarding.md).

## Network hardening

| Endpoint | Auth | Recommendation |
|----------|------|----------------|
| `/health`, `/ready` | None | Internal probes only |
| `/metrics` | None | Restrict with NetworkPolicy |
| `/pki/ocsp/:id` | None | Public OCSP by design |
| All other routes | Bearer token | Require TLS at ingress |

Optional controls:

- `KNXVAULT_RATE_LIMIT_ENABLED` — per-token/IP throttling
- `KNXVAULT_REQUEST_SIGNING_REQUIRED` — HMAC request signatures

## Container security

The **only** production image path (`Dockerfile`):

- Multi-stage build: `golang:1.26-bookworm` builder → `gcr.io/distroless/static-debian13:nonroot` runtime
- Runs as non-root (uid 65532)
- Static binaries only (knxvault, knxvault-csi, knxvault-webhook, knxvault-eso) — **no shell, no OpenSSL CLI**
- PKI is always native Go `crypto/x509` (OpenSSL CLI backend removed from the binary)

CI gates: `gosec`, `golangci-lint`, Trivy vulnerability and license scan, SPDX allow-list.

## Storage classification in Raft

| Stored in Raft | Encrypted? | Notes |
|----------------|------------|-------|
| Secret values, CA private keys | **Yes** | Envelope encryption before `Propose` |
| CA certificate PEM | No | Public by design |
| Secret paths, versions, TTL | No | Required for RBAC and routing; see ADR-0005 |
| RBAC policies and roles | No | No secret payloads; architecture metadata |
| Audit log entries | No | `details` redacted; `resource` paths kept for compliance |
| Database role `config` | No | Must not contain credentials; API validates |

Path encryption is **not implemented** — significant complexity with limited benefit vs. separate vault instances per classification level. See [ADR-0005](../adr/0005-cleartext-metadata-in-raft.md).

## Database role and audit controls

- **Database roles:** `config` rejects passwords, tokens, and connection URLs. Store admin creds in KV; set `admin_credentials_path` for runbooks. Prefer passwordless DB admin (IAM, cert auth) where possible. See [operator security](../operations/operator-security.md).
- **Audit logs:** `details` fields are **stripped** before persistence — sensitive keys and credential-like strings become `[REDACTED]`. Operations are not failed if a caller accidentally includes a sensitive key (strip policy). Do not log secret values intentionally.

## Compliance posture

KNXVault provides auditability and encryption primitives suitable for regulated environments, but does not ship pre-built compliance packs (SOC2, PCI-DSS). Operators are responsible for:

- Key custody procedures
- Backup encryption and retention
- Ingress TLS and network segmentation
- Access review of policies and tokens

Phase 4 may add compliance export bundles; see [Phase 4 design](../design/phase4-ecosystem.md).

## Kubernetes TLS automation security notes

| Control | Guidance |
|---------|----------|
| **Prefer operator over long-lived vault tokens in cert-manager** | Operator uses SA JWT → scoped policies; avoid static root tokens |
| **AppRole secret_id** | Store only in K8s Secrets; register via `POST /sys/auth/approle` (sudo); rotate by re-register |
| **Certificate delivery `None`** | Avoid putting leaf private keys in etcd when apps can use CSI/API |
| **Issuer Ready** | Operator marks Issuer Ready only when vault CA exists — prevents silent misconfig |
| **Operational seal** | `POST /sys/seal` blocks mutating APIs; cert-manager health returns 503 until unseal |

## Related documents

- [Replace cert-manager](../operations/pki-replace-cert-manager.md)
- [cert-manager Vault profile](../recipes/cert-manager-integration.md)
- [Runbook: CA compromise](../operations/runbooks/ca-compromise.md)
- [Configuration reference](../installation/configuration.md)
- [Licensing policy](../licensing.md)