# ADR-0001: Dragonboat Raft Storage Backend

**Status:** Accepted  
**Date:** 2026  
**Supersedes:** Interim PostgreSQL backend

## Context

KNXVault initially used PostgreSQL for persistence with Kubernetes Lease-based leader election for background jobs. This introduced an external operational dependency (Postgres HA operator) and split consistency concerns between the database and the application.

Production secrets vaults require:

- Strong consistency for writes
- Built-in HA without an external consensus store
- Encrypted snapshots for backup/restore
- Single-binary deployment option

## Decision

Adopt [Dragonboat v3](https://github.com/lni/dragonboat) as the primary storage backend:

- Single Raft cluster (ID `1`) with a custom state machine in `internal/raft/`
- Repository interfaces unchanged; Dragonboat adapters in `internal/repository/dragonboat/`
- Pebble WAL as the default Dragonboat log store
- 3-node StatefulSet topology for production HA
- Raft leader gates background jobs (lease cleanup, CRL refresh, cert renewal)
- PostgreSQL deprecated; migration via `knxvault-cli migrate postgres`

## Consequences

### Positive

- No external database required for production
- Linearizable writes through Raft consensus
- Leader election unified with storage layer
- Snapshot/backup format aligned with `internal/backup.Snapshot`

### Negative

- Fixed 3-node topology in v0.1.x; dynamic membership not yet automated
- Dragonboat transitive dependencies include MPL-2.0 (documented license exception)
- LLD §4.D still references PostgreSQL — requires revision

### Follow-up

- Phase 4: evaluate 5-node clusters, read replicas, DR automation
- Full LLD update for storage section
- Remove PostgreSQL code path after migration window closes

## References

- [Dragonboat storage design](../storage/dragonboat.md)
- [Raft failover runbook](../operations/runbooks/raft-failover.md)