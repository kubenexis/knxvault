# ADR-0005: Cleartext Metadata in Raft Storage

**Status:** Accepted  
**Date:** 2026

## Context

KNXVault encrypts secret values and private keys before Dragonboat replication ([ADR-0004](0004-encrypt-before-replication.md)). Operators asked whether additional Raft fields should also be encrypted: CA certificates, secret paths, RBAC policies, and audit logs.

Encrypting all Raft payloads would maximize confidentiality of metadata but conflicts with operability, RBAC path matching, and audit compliance requirements.

## Decision

**Keep the following in cleartext in Raft state, WAL, and snapshots:**

| Category | Examples | Reason |
|----------|----------|--------|
| CA certificate PEM | `cert_pem` on `CA` entities | Public material by X.509 design |
| RBAC policies and roles | Path patterns, capabilities, SA bindings | Policy evaluation requires readable paths |
| Audit log entries | Actor, action, resource path, status | Compliance review and hash-chain verification |
| Secret metadata | Path, version, TTL, `expires_at` | Listing, injection, RBAC, and routing |
| PKI metadata | Serial, CN, SANs, expiry | CRL, OCSP, renewal jobs |

**Encrypt before replication (unchanged):**

- KV secret payloads (`data_enc`, `dek_enc`)
- CA private keys (`private_key_enc`, `dek_enc`)
- Ephemeral database credentials (stored as KV secrets)
- Portable backup blobs (`backup.Seal`)

**Explicitly not implemented:**

- **Path encryption** — deferred; high complexity (encrypted index, searchable encryption, or blind RBAC). Organizations requiring path hiding should deploy separate vault clusters per classification boundary.

## Consequences

### Positive

- RBAC `path_prefix` and `secrets/kv/*` globs work without decryption
- Audit export and verification remain human-readable
- OCSP/CRL and CA distribution use standard PEM handling
- Aligns with common vault product trade-offs

### Negative

- Raft disk access reveals path names and policy structure (metadata leakage)
- Audit `resource` fields expose which paths were accessed
- Attackers can map infrastructure without the master key

### Mitigations

- Restrict Raft PVC and backup access (RBAC, encryption at rest for volumes)
- NetworkPolicy on KNXVault pods
- Least-privilege RBAC policies
- Audit `details` redaction ([operator security](../operations/operator-security.md))

## References

- [Security model](../architecture/security-model.md)
- [Operator security guidance](../operations/operator-security.md)