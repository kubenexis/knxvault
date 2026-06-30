# Low-Level Design (LLD)

The canonical Low-Level Design document lives at [`../lld.md`](../lld.md).

It contains sections 1–12 covering introduction, system architecture, module layout, cryptographic design, API specification, deployment, security, testing, roadmap, risks, and documentation strategy.

> **Note:** LLD §4.D and §2.1 still reference PostgreSQL in places. The production storage backend is Dragonboat Raft as documented in [`../storage/dragonboat.md`](../storage/dragonboat.md) and [ADR-0001](../adr/0001-dragonboat-storage-backend.md). A full LLD revision is tracked in the backlog.