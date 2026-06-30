# ADR-0001: Dragonboat Raft Storage Backend

**Status:** Accepted  
**Date:** 2026

## Context

KNXVault was designed with embedded consensus from the start. Early development used in-memory repositories for fast iteration; production deployments always target Dragonboat Raft with no external database.

Production secrets vaults require:

- Strong consistency for writes
- Built-in HA without an external consensus store
- Encrypted snapshots for backup/restore
- Single-binary deployment option

## Decision

Adopt [Dragonboat v3](https://github.com/lni/dragonboat) as the storage backend:

- Single Raft cluster (ID `1`) with a custom state machine in `internal/raft/`
- Repository interfaces unchanged; Dragonboat adapters in `internal/repository/dragonboat/`
- Pebble WAL as the default Dragonboat log store
- 3-node StatefulSet topology for production HA
- Raft leader gates background jobs (lease cleanup, CRL refresh, cert renewal)
- Development and CI use in-memory repositories when `KNXVAULT_RAFT_ENABLED` is unset

## Consequences

### Positive

- No external database required for production
- Linearizable writes through Raft consensus
- Leader election unified with storage layer
- Snapshot/backup format aligned with `internal/backup.Snapshot`

### Negative

- Fixed 3-node topology in v0.1.x; dynamic membership not yet automated
- Dragonboat transitive dependencies include MPL-2.0 (documented license exception)

### Follow-up

- Phase 4: evaluate 5-node clusters, read replicas, DR automation

## References

- [Dragonboat storage design](../storage/dragonboat.md)
- [Raft failover runbook](../operations/runbooks/raft-failover.md)