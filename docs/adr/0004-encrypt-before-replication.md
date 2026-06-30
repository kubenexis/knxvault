# ADR-0004: Encrypt Before Replication

**Status:** Accepted  
**Date:** 2026

## Context

KNXVault replicates vault state through a Dragonboat Raft cluster. Raft persists:

- Command entries in the Pebble WAL
- Periodic state-machine snapshots on disk
- In-memory state on each replica

An attacker with read access to Raft storage (PVC, backup files, stolen disk) must not recover plaintext secrets without the master key. Replication transports serialized state between nodes and must never carry cleartext secret material.

## Decision

**All secret and key material is encrypted at the engine layer before any repository write or Raft propose.**

Required flow for KV secrets:

```
PutSecret (API)
    → KVV2Engine.Put
    → json.Marshal(data)
    → crypto.Seal (AES-256-GCM envelope: DEK + master-wrapped DEK)
    → SecretVersion{DataEnc, DEKEnc}
    → repository.SaveVersion
    → Raft Propose (secret.save_version)
    → Pebble WAL / snapshot (ciphertext only)
```

The same invariant applies to:

| Material | Encrypt location | Raft field |
|----------|------------------|------------|
| KV secret payloads | `KVV2Engine.Put` | `data_enc`, `dek_enc` |
| Dynamic DB credentials | `database.Engine.storeSecret` | same as KV |
| CA / intermediate private keys | `pki.Engine` | `private_key_enc`, `dek_enc` |
| Portable backups | `backup.Seal` | entire snapshot blob |

Raft commands carry **already-encrypted** byte slices. The Dragonboat log and snapshots contain JSON with base64-encoded ciphertext — not plaintext secrets.

### What remains intentionally unencrypted in Raft

| Data | Rationale |
|------|-----------|
| CA certificate PEM | Public material |
| Secret paths, versions, TTL metadata | Required for routing; not secret values |
| RBAC policies and roles | Authorization config; no secret payloads |
| Audit log entries | Compliance visibility; must not include secret values in `details` |
| Issued cert metadata | Public certificate fields |

### Database role configuration

`DatabaseRole.Config` accepts **non-secret tuning only** (`db_type`, `ssl_mode`, `database_name`). Credential-like keys and embedded connection URLs are **rejected at validation**. Admin database credentials belong in KV (`secrets/kv/database/admin/...`) and are referenced via `admin_credentials_path` for runbooks. See [Database credentials](../deploy/database-credentials.md).

## Consequences

### Positive

- Raft quorum compromise does not expose secrets without the master key
- Snapshots and WAL inspection shows ciphertext only for secret bodies
- Aligns with industry practice (Vault, etc.): encryption at the application layer, replication of sealed blobs

### Negative

- Master key loss is catastrophic (by design)
- Raft payloads are larger (ciphertext + wrapped DEK overhead)
- Per-entry envelope encryption; no additional full-log encryption layer (master key still required for DEK unwrap)

### Follow-up

- Encrypt `DatabaseRole.Config` when it contains credentials
- Optional Raft transport TLS between peers (network layer, separate from this ADR)
- Audit redaction guard: reject `details` fields that resemble secret values

## References

- [ADR-0003](0003-envelope-encryption.md) — envelope encryption
- [Security model](../architecture/security-model.md)
- `internal/engine/secrets/kvv2.go` — `Put` seals before `SaveVersion`
- `internal/raft/store.go` — state machine persists sealed domain objects