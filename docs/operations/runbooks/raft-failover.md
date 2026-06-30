# Runbook: Raft Failover and Recovery

**Severity:** High (quorum loss) / Medium (single node failure)  
**Cluster:** 3-node Dragonboat Raft StatefulSet

## Normal operation

- One node holds `knxvault_raft_leader = 1`
- `knxvault_raft_commit_index` advances on writes
- `/ready` returns `raft_ready: true` and names the current `leader`
- Background jobs run only on the leader

## Scenario 1: Single node failure (2/3 quorum intact)

**Symptoms:** One pod `CrashLoopBackOff`; cluster still accepts writes.

**Actions:**

1. Check pod logs: `kubectl -n knxvault logs knxvault-N`
2. Verify PVC is bound: `kubectl -n knxvault get pvc`
3. Delete the failed pod — StatefulSet recreates it:

```bash
kubectl -n knxvault delete pod knxvault-N
```

4. Wait for `/ready` on the replacement pod
5. The replacement rejoins the cluster and catches up from the Raft log

No data loss expected. Leader may transfer during the outage.

## Scenario 2: Leader pod failure

**Symptoms:** Brief write latency spike; `knxvault_raft_leader` changes to another replica.

**Actions:**

1. Confirm new leader elected within ~10–30 seconds
2. Verify `knxvault_raft_commit_index` resumes advancing
3. No operator action required if quorum is intact

## Scenario 3: Quorum loss (2+ nodes down)

**Symptoms:** Writes fail; `/ready` returns 503; `raft_ready: false`.

**Actions:**

1. Restore at least **2 of 3** nodes with intact PVCs
2. If PVCs are corrupted, restore from backup:

```bash
# On a fresh single-node cluster for disaster recovery
export KNXVAULT_RAFT_ENABLED=true
export KNXVAULT_RAFT_NODE_ID=1
# ... other Raft vars ...

./bin/knxvault-cli backup restore -f knxvault-backup.json
```

3. Re-expand to 3 nodes after state is verified on the recovery node

> **Warning:** Never run two independent Raft clusters with the same `KNXVAULT_RAFT_INITIAL_MEMBERS` against divergent data sets. This causes split-brain.

## Scenario 4: Full cluster loss (all PVCs destroyed)

**Severity:** Critical

1. Provision a new 3-node StatefulSet
2. Restore from the most recent encrypted backup (`POST /sys/restore` or CLI)
3. Verify secrets, CAs, and policies
4. Re-issue any certificates that were created after the backup timestamp

```bash
./bin/knxvault-cli backup restore -f knxvault-latest.json
curl -s http://knxvault:8200/ready
```

## Scenario 5: Network partition

**Symptoms:** Split views of leadership; writes fail on minority partition.

**Actions:**

1. Identify the partition with **majority** (2 nodes that can reach each other)
2. Isolate or repair networking on the minority node
3. Minority node rejoins automatically when connectivity restores

Dragonboat does not support asymmetric quorums — maintain network connectivity between all replicas.

## Diagnostic commands

```bash
# Per-pod readiness
kubectl -n knxvault exec knxvault-0 -- wget -qO- http://localhost:8200/ready

# Raft metrics
kubectl -n knxvault port-forward svc/knxvault 8200:8200
curl -s localhost:8200/metrics | grep knxvault_raft

# PVC usage
kubectl -n knxvault exec knxvault-0 -- df -h /var/lib/knxvault/raft
```

## Recovery verification checklist

- [ ] `/ready` returns 200 on all replicas
- [ ] Exactly one `knxvault_raft_leader = 1`
- [ ] Write + read secret round-trip succeeds
- [ ] Background jobs running (check leader pod logs for lease cleanup)
- [ ] `knxvault_raft_commit_index` increasing under load

## Related documents

- [Dragonboat storage](../../storage/dragonboat.md)
- [Backup & restore](../../deploy/backup-restore.md)
- [Scaling runbook](scaling.md)