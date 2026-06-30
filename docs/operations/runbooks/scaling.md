# Runbook: Scaling KNXVault

## Current limits

KNXVault production HA is designed for a **fixed 3-node Raft cluster**. Dragonboat cluster membership changes (add/remove nodes) are not automated in the current release.

| Dimension | Current support | Notes |
|-----------|-----------------|-------|
| Raft replicas | 3 (fixed) | StatefulSet in `deployments/k8s/` |
| HTTP throughput | Vertical | Scale CPU/memory per replica |
| Read load | Any replica | All nodes serve API; writes go through Raft leader |
| Storage | Per-replica PVC | Grows with secrets, audit, and Raft log |

## Vertical scaling

Increase CPU and memory limits in `statefulset.yaml`:

```yaml
resources:
  requests:
    cpu: "500m"
    memory: "512Mi"
  limits:
    cpu: "2"
    memory: "2Gi"
```

Rolling restart one pod at a time. Monitor `knxvault_http_request_duration_seconds` p99 after changes.

## Storage scaling

1. Monitor PVC usage: `kubectl -n knxvault exec knxvault-0 -- df -h /var/lib/knxvault/raft`
2. Expand the StorageClass volume (if supported) or migrate to a larger PVC
3. Dragonboat compacts logs via snapshots — ensure backup schedule is healthy

Audit log growth is the primary long-term storage driver. Export and archive audit data periodically via `GET /audit/export`.

## Performance tuning

| Knob | Default | Effect |
|------|---------|--------|
| `KNXVAULT_RATE_LIMIT_RPM` | 300 | Increase for high-throughput trusted clients |
| `KNXVAULT_RAFT_ELECTION_RTT` | 10 | Lower = faster failover, more CPU |
| `KNXVAULT_RAFT_HEARTBEAT_RTT` | 1 | Lower = tighter leader detection |
| `KNXVAULT_OPENSSL_TIMEOUT` | 60s | Reduce for faster PKI failure detection |

PKI operations are CPU-bound (OpenSSL subprocess). For high issuance rates, dedicate larger CPU limits to the Raft leader pod.

## HTTP load distribution

The ClusterIP Service load-balances HTTP across all replicas. Writes are forwarded internally through Raft propose on whichever node receives the request — only the leader commits, but any node can accept the HTTP call.

For very high read traffic, consider:

- Client-side caching of public CA certificates and CRLs
- Phase 4 Redis read cache (not yet implemented)

## Multi-cluster scaling (future)

Phase 4 multi-tenancy may introduce namespace-isolated vault instances. Until then, deploy separate KNXVault clusters per environment (dev/staging/prod) rather than expanding a single Raft group beyond 3 nodes.

## Adding a 4th Raft node

Not supported in v0.1.x. Requires:

- Dragonboat membership change API
- Updated `KNXVAULT_RAFT_INITIAL_MEMBERS`
- Operational runbook for joint consensus

Track as Phase 4+ work. See [Phase 4 design](../../design/phase4-ecosystem.md).

## Related documents

- [Kubernetes deployment](../../deploy/kubernetes.md)
- [Metrics](../../metrics.md)
- [Raft failover runbook](raft-failover.md)