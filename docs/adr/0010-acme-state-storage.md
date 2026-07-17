<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR-0010: ACME state storage (file-first; optional vault later)

**Status:** Accepted  
**Date:** 2026-07-17  
**Milestone:** M-ACME-1 / M-ACME-2 (W60-15)

## Context

Unified ACME needs to persist account keys and certificate metadata for renew. Options:

1. **Filesystem only** (host CLI / standalone)  
2. **Kubernetes Secrets only** (operator)  
3. **KNXVault Raft-backed API** for multi-admin shared state  

## Decision

**M-ACME-1:** File system for standalone/CLI; Kubernetes Secrets for operator account keys (existing). No Raft ACME engine in M-ACME-1.

**M-ACME-2 (optional):** Encrypted ACME metadata via existing KV or a dedicated sealed path **only if** multi-admin fleets require shared renew without shared disk. Default remains file + operator Secrets.

## Consequences

- Distroless server image stays free of ACME challenge listeners.  
- CLI renew works offline from knxvault process (needs LE network only).  
- Vault-stored ACME is explicit opt-in later (`--store=vault` / W60-16), not default.
