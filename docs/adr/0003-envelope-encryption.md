<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0003: Envelope Encryption with Master Key

**Status:** Accepted  
**Date:** 2025

## Context

Secrets and CA private keys must be encrypted at rest. The encryption scheme must:

- Limit blast radius of a single key compromise to one object
- Support offline backup/restore with a stable format
- Avoid storing plaintext DEKs in Raft state or logs

## Decision

Implement **envelope encryption** in `internal/crypto/service.go`:

1. Generate a random 256-bit DEK per secret version or CA key
2. Encrypt payload with AES-256-GCM using the DEK
3. Wrap the DEK with the 32-byte master key (also AES-256-GCM)
4. Persist `DataEnc` + `DEKEnc` in storage

Master key loading:

- `KNXVAULT_MASTER_KEY` (base64) or `KNXVAULT_MASTER_KEY_FILE`
- Required at startup; process refuses to serve secrets without it

Backup archives encrypt the full snapshot payload with the same master key.

## Consequences

### Positive

- Per-object DEK limits exposure scope
- Master key never stored in Raft log
- Backup format reuses envelope primitives

### Negative

- Master key rotation requires re-encryption of all wrapped DEKs (leader background job)
- Loss of master key means permanent data loss
- Operators must manage master key custody (K8s Secret, KMS, etc.)

### Follow-up

- External KMS integration for master key unwrap
- HSM-backed master key via OpenSSL engine

**Implemented (Phase 4):** `POST /sys/rotate-master-key`, versioned `KeyRing`, DEK re-encrypt job — see [Envelope encryption](../architecture/envelope-encryption.md).

## References

- [Security model](../architecture/security-model.md)
- [Data models](../architecture/data-models.md)
- `internal/crypto/service.go`