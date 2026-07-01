# Raft Cluster Scaling Runbook

This runbook covers adding and removing voting members in a running KNXVault Dragonboat cluster (W36-23).

## Prerequisites

- Quorum healthy (`GET /ready` → `raft_ready: true`)
- Admin token with `sys/raft:write`
- New node provisioned with empty Raft data dir and `KNXVAULT_RAFT_JOIN=true`

## Add a fourth replica

1. Deploy the new pod/VM with a **new** node ID (e.g. `4`) and reachable Raft address.
2. Set on the new member only:

```bash
export KNXVAULT_RAFT_NODE_ID=4
export KNXVAULT_RAFT_ADDRESS=10.0.0.4:63001
export KNXVAULT_RAFT_JOIN=true
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=10.0.0.1:63001,2=10.0.0.2:63001,3=10.0.0.3:63001,4=10.0.0.4:63001
```

3. Start the new process and wait for it to listen on the Raft port.
4. From any **leader** (or via load-balanced API to leader), call:

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/raft/add-node" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"node_id":4,"address":"10.0.0.4:63001"}'
```

5. Verify: `curl -s $KNXVAULT_ADDR/ready | jq` on all replicas; write a KV secret and read from the new follower.

## Remove a replica

1. Drain HTTP traffic from the target replica.
2. On a leader:

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/raft/remove-node" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"node_id":4}'
```

3. Stop the removed process. **Do not** reuse the same node ID for a different host without treating it as a new member.

## Rollback

If `add-node` fails mid-flight:

- Stop the new member before it joins production traffic.
- If the config change committed but the node is unhealthy, call `remove-node` for that ID.
- Restore `KNXVAULT_RAFT_INITIAL_MEMBERS` in ConfigMap to match the stable member set for future joins.

## Kubernetes notes

- Update the headless Service and StatefulSet replica count **after** successful `add-node`.
- New pods should use `KNXVAULT_RAFT_JOIN=true` and omit writing to an existing peer data directory.
- See [`docs/storage/dragonboat.md`](../../storage/dragonboat.md) for node ID assignment and [Raft HA & recovery](../../storage/raft-ha-and-recovery.md) for membership change semantics.