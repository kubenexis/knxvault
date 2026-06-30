# Security Model

Threat assumptions, cryptographic controls, and operational security guidance for KNXVault.

## Threat model

| Threat | Impact | Mitigations |
|--------|--------|-------------|
| Master key compromise | All secrets and CA keys recoverable | K8s Secret sealing, short exposure window, backup key custody, future rotation API |
| Raft quorum loss | Write unavailability | 3-node cluster, PVC backups, documented failover runbook |
| Token theft | Unauthorized API access | Short TTL, RBAC least privilege, rate limiting, optional request signing |
| OpenSSL sandbox escape | Host compromise | Argument validation, `0700` temp dirs, timeouts, non-root container |
| Audit tampering | Compliance failure | Hash-chained log, HMAC export signatures, Raft replication |
| Network eavesdropping | Credential exposure | TLS at ingress (operator responsibility); mTLS planned Phase 4 |

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

### PKI operations

All X.509 operations execute via the OpenSSL CLI in an isolated temporary directory:

- Configurable binary path and timeout
- No user-controlled OpenSSL config paths
- See [ADR-0002](../adr/0002-openssl-cli-crypto-backend.md)

## Authentication

| Method | Use case | Configuration |
|--------|----------|---------------|
| Bootstrap root token | Initial admin | `KNXVAULT_ROOT_TOKEN` |
| Opaque client tokens | Automation, CLI | Issued after `/auth/token` validation |
| Kubernetes JWT | In-cluster workloads | `KNXVAULT_JWT_SECRET` (HS256 validation) |

Tokens carry a TTL (`KNXVAULT_TOKEN_TTL`, default 24h). The root token should be rotated or disabled after bootstrap policies are established.

## Authorization (RBAC)

Policies grant capabilities on path prefixes:

| Capability | Typical paths |
|------------|---------------|
| `read` | `secrets/kv/*`, `pki/ca/*` |
| `write` | `secrets/kv/*`, `pki/*` |
| `delete` | `secrets/kv/*` |
| `sudo` | `sys/*`, `audit/*` |

Conditions restrict by source IP, time window, K8s namespace, or path prefix. Evaluated in `internal/auth/evaluator.go` before handler execution.

Default bootstrap policy `admin` grants full access. Production clusters should define scoped policies per workload.

## Audit

Every sensitive operation appends to the hash-chained audit log:

```
hash(n) = SHA-256(prev_hash || entry_payload)
```

Export via `GET /audit/export` includes the chain head and optional HMAC signature (`KNXVAULT_AUDIT_SIGNING_KEY`). Verify with `POST /audit/verify`.

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

## Database role and audit controls

- **Database roles:** `config` rejects passwords, tokens, and connection URLs. Use `admin_credentials_path` to document where KV admin creds live; store admin creds in the secrets engine.
- **Audit logs:** `details` fields are redacted before persistence (`password`, `connection_url`, credential-like strings → `[REDACTED]`).

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