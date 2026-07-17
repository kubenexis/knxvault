<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Low-Level Design (LLD)

The canonical Low-Level Design document lives at [`../lld.md`](../lld.md).

It contains sections 1–12 covering introduction, system architecture, module layout, cryptographic design, API specification, deployment, security, testing, roadmap, risks, and documentation strategy.

Production storage is **Dragonboat Raft** (see [`../storage/dragonboat.md`](../storage/dragonboat.md) and [ADR-0001](../adr/0001-dragonboat-storage-backend.md)). Development uses in-memory repositories when Raft is disabled.