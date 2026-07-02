# Security Model

Threat assumptions, cryptographic controls, and operational security guidance for KNXVault.

## Threat model

| Threat | Impact | Mitigations |
|--------|--------|-------------|
| Master key compromise | All secrets and CA keys recoverable | K8s Secret sealing, short exposure window, backup key custody, `POST /sys/rotate-master-key` |
| Raft quorum loss | Write unavailability | 3-node cluster, PVC backups, documented failover runbook |
| Token theft | Unauthorized API access | Short TTL, RBAC least privilege, rate limiting, optional request signing |
| OpenSSL sandbox escape | Host compromise | Argument validation, `0700` temp dirs, timeouts, non-root container |
| Audit tampering | Compliance failure | Hash-chained log, HMAC export signatures, Raft replication |
| Network eavesdropping | Credential exposure | TLS at ingress (operator responsibility); server TLS (**W37-01**, shipped) and Raft peer mTLS (**W38-14**, shipped); broader route mTLS → Phase 5 **W34-01** |

## Cryptography

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

All X.509 operations execute via the OpenSSL CLI in an isolated temporary directory:

- Configurable binary path and timeout
- No user-controlled OpenSSL config paths
- See [ADR-0002](../adr/0002-openssl-cli-crypto-backend.md)

## Authentication

| Method | Use case | Configuration | Status |
|--------|----------|---------------|--------|
| Bootstrap root token | Initial admin | `KNXVAULT_ROOT_TOKEN` | Production |
| Opaque client tokens | Automation, CLI | `POST /auth/token/create`, renew, revoke | Production |
| Kubernetes ServiceAccount | In-cluster workloads | TokenReview (in-cluster) | **Production** |
| Kubernetes JWT (HS256) | Local dev only | `KNXVAULT_JWT_SECRET` | Dev-only |
| K8s login bypass | Local dev only | `KNXVAULT_K8S_AUTH_INSECURE=true` | Dev-only (never with Raft); parses JWT `sub` without verification |

### Kubernetes authentication (production)

When KNXVault runs in a Kubernetes cluster, `POST /auth/kubernetes` validates the caller's ServiceAccount JWT via the **`authentication.k8s.io/v1` TokenReview** API (`internal/infra/k8s/tokenreview.go`). The API server confirms token authenticity; KNXVault maps the reviewed SA to a vault role.

**Fail-closed behavior:** If Raft is enabled (production mode) and neither TokenReview nor an explicit dev bypass is configured, login is rejected with `401`. Arbitrary JWT strings cannot mint client tokens.

**Role bindings:** Roles may restrict login to specific service accounts via `bound_service_account_names` and `bound_service_account_namespaces`. A successful TokenReview with a non-matching SA returns `403`.

**Auth method enforcement:** Roles with `auth_method: "oidc"` reject Kubernetes login; roles with `auth_method: "kubernetes"` reject OIDC login. K8s login resolves `policy_groups` the same way as OIDC.

**OIDC JWT requirements:** OIDC login rejects JWTs without an `exp` claim. Machine identity revocation checks fail closed when the NHI backend is unavailable.

**Login lockout (W43-04):** Failed `/auth/kubernetes` and `/auth/oidc/*` attempts are tracked **per source IP** (`LoginLockoutKey`). After `KNXVAULT_AUTH_LOCKOUT_THRESHOLD` failures within the window, further logins from that IP are rejected until TTL expiry or successful login clears the counter.

**ABAC environment (W44-02):** Send `X-KNX-Environment` on API requests when policies use `environment` conditions. The header is copied into `RequestContext` after authentication.

**Dev-only paths:** `KNXVAULT_JWT_SECRET` enables HS256 validation for local testing. `KNXVAULT_K8S_AUTH_INSECURE=true` parses JWT structure without signature verification when Raft is disabled — still requires a `system:serviceaccount:…` subject for SA binding checks; never enable in production.

**HA client tokens:** When Raft is enabled, opaque client tokens (root, `POST /auth/token/create`, K8s login) are replicated via `token.save` / `token.get` / `token.revoke` Raft commands. Tokens survive node restarts and authenticate on any cluster member.

**RBAC cluster sync:** Each node reloads persisted policies from Raft before `Authorize` when the policy set hash changes, so policy writes on the leader are visible on followers without restart. `SyncRBAC` holds an exclusive lock across list-and-reload to avoid overwriting concurrent policy updates with a stale snapshot.

Tokens carry a TTL (`KNXVAULT_TOKEN_TTL`, default 24h). The root token should be rotated or disabled after bootstrap policies are established.

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

**KV path normalization:** Secret API paths containing `..` are rejected before authorization. Invalid `?version=` on DELETE returns `400` instead of `500`.

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

The production image:

- Multi-stage build, minimal runtime base
- Runs as non-root
- Includes only OpenSSL and the static binary

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

## Related documents

- [Runbook: CA compromise](../operations/runbooks/ca-compromise.md)
- [Configuration reference](../installation/configuration.md)
- [Licensing policy](../licensing.md)