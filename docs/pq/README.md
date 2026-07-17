<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Post-quantum (PQ) readiness — documentation index

This section captures the **assessment**, **discussion**, and **planned way forward** for post-quantum readiness in KNXVault. It is design and backlog guidance — **KNXVault is not PQ-ready today**.

| Field | Value |
|-------|-------|
| **Status** | Classical crypto in production paths; AES-256 at rest is relatively durable; PKI/TLS are not PQ |
| **Audience** | Architects, security, maintainers |
| **Product claim** | Do **not** market “post-quantum ready” until backlog gates in [backlog.md](backlog.md) complete |

## Documents

| Document | Description |
|----------|-------------|
| [**Design & architecture discussion**](design-and-architecture-discussion.md) | Full narrative of the PQ design discussion, decisions, and open questions |
| [Current state](current-state.md) | What algorithms KNXVault uses today and PQ implications |
| [Roadmap & way forward](roadmap.md) | Phased approach (PQ-0 … PQ-5), priority order, what not to do |
| [Dual crypto planes](dual-crypto-planes.md) | Classical + PQ coexistence; abstraction; Harbor/K8s compatibility |
| [Crypto generations (g1 / g2 / g3)](crypto-generations.md) | Generation contracts; who chooses gN; Harbor never calls gN |
| [**PQ backlog**](backlog.md) | Standalone work items **PQ-*** (separate from main [docs/backlog.md](../backlog.md)) |

## One-paragraph summary

At rest, KNXVault already uses **AES-256-GCM** with random DEKs and master-wrapped DEKs — a reasonable classical baseline under Grover-style threats if master-key custody is strong. **PKI** (RSA) and **TLS** (classical handshake and certs) are **not** post-quantum. The recommended path is: document and harden classical crypto; add **algorithm agility** and **crypto generations** (`g1` = legacy-safe default); run **dual planes** so Harbor and legacy apps stay on **g1** while PQ-capable apps opt into **g2+**; introduce hybrid TLS (edge or in-process) and PQ signatures only when client matrices allow. Envelope crypto stays shared AES for all planes.

## Related product docs

- [Security model](../architecture/security-model.md)
- [Envelope encryption](../architecture/envelope-encryption.md)
- [Operator runbook](../operations/operator-runbook.md)
- [Certificate support matrix](../operations/certificate-support-matrix.md)
- knxctl stack process (separate repo): `primary-cluster-stack/docs/knxvault-instead-of-cert-manager-for-harbor.md`
