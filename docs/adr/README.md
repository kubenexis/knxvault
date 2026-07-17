<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Architecture Decision Records (ADRs)

ADRs document significant architectural decisions with context, options considered, and consequences.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-dragonboat-storage-backend.md) | Dragonboat Raft storage backend | Accepted |
| [0002](0002-openssl-cli-crypto-backend.md) | OpenSSL CLI as cryptographic backend | Accepted |
| [0003](0003-envelope-encryption.md) | Envelope encryption with master key | Accepted |
| [0004](0004-encrypt-before-replication.md) | Encrypt before Raft replication | Accepted |
| [0005](0005-cleartext-metadata-in-raft.md) | Cleartext metadata in Raft (paths, RBAC, audit, CA PEM) | Accepted |

## Format

New ADRs follow the template in each existing record:

1. **Status** — Proposed, Accepted, Deprecated, Superseded
2. **Context** — Problem statement
3. **Decision** — What was chosen
4. **Consequences** — Positive, negative, and follow-up work

Number sequentially: `docs/adr/NNNN-short-title.md`.

## When to write an ADR

- Storage, crypto, or auth architecture changes
- New runtime dependencies (especially license exceptions)
- Breaking API or snapshot format changes
- Deprecation of major components

License exceptions also require an entry in [`docs/licensing.md`](../licensing.md).