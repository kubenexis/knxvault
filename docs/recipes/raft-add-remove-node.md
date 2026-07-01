# Recipe: Add and remove Raft nodes

Change cluster membership on a running Dragonboat cluster without data loss.

## What you will learn

- When to add vs remove voting members
- `POST /sys/raft/add-node` and `POST /sys/raft/remove-node`
- Kubernetes StatefulSet considerations

## Prerequisites

- Healthy 3-node cluster (`raft_ready: true` on majority)
- Admin token with `sys/raft:write`
- Quorum never drops below majority during removal

## Concepts

| Rule | Detail |
|------|--------|
| **Node ID** | Stable integer per member; never reuse on a different host |
| **Leader only** | Membership changes must reach the Raft leader |
| **Join mode** | New members start with `KNXVAULT_RAFT_JOIN=true` and empty data dir |
| **Remove** | Call API first, then stop the pod — do not delete data and rejoin with same ID casually |

## Remove a node (3 → 2 temporarily)

Use when replacing a failed replica or shrinking the cluster.

### 1. Confirm quorum

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

curl -s $KNXVAULT_ADDR/ready | jq .
knxvault-cli kv put membership/test value=before-removal
```

### 2. Remove node 3 (knxvault-2)

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/raft/remove-node" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"node_id":3}' | jq .

# CLI equivalent
knxvault-cli sys raft-remove-node --node-id 3
```

### 3. Stop the removed member

```bash
kubectl -n knxvault delete pod knxvault-2 --wait=true
# Scale StatefulSet to 2 replicas OR leave pod deleted during maintenance
```

### 4. Verify cluster still writable

```bash
knxvault-cli kv put membership/test value=after-removal
knxvault-cli kv get membership/test --show-secrets
```

## Add a node back (2 → 3)

### 1. Prepare replacement pod

- Fresh empty Raft data directory (or new PVC)
- `KNXVAULT_RAFT_JOIN=true`
- Correct `KNXVAULT_RAFT_NODE_ID` (e.g. `3` for `knxvault-2`)
- `KNXVAULT_RAFT_ADDRESS` pointing to headless Service DNS

Update ConfigMap if member list changed.

### 2. Start the pod

```bash
kubectl -n knxvault scale statefulset knxvault --replicas=3
kubectl -n knxvault wait --for=condition=ready pod/knxvault-2 --timeout=600s
```

### 3. Register with cluster

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/raft/add-node" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "node_id": 3,
    "address": "knxvault-2.knxvault-raft.knxvault.svc.cluster.local:63001"
  }' | jq .

knxvault-cli sys raft-add-node --node-id 3 \
  --address knxvault-2.knxvault-raft.knxvault.svc.cluster.local:63001
```

### 4. Verify catch-up

```bash
kubectl -n knxvault exec knxvault-2 -- wget -qO- http://localhost:8200/ready | jq .
knxvault-cli kv get membership/test --show-secrets
```

## Add a fourth replica (scale out)

See full procedure in [Scaling runbook](../operations/runbooks/scaling.md):

1. Deploy new VM/pod with **new** node ID (`4`).
2. Set `KNXVAULT_RAFT_JOIN=true`.
3. Call `add-node` with `node_id: 4` and reachable address.
4. Verify write/read on all four members.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `add-node` fails | Ensure target listens on Raft port; call via leader/service |
| Stuck `raft_ready: false` | ID/address mismatch in `INITIAL_MEMBERS` |
| Data corruption after ID reuse | Treat as new member — wipe data dir, rejoin |

## Related recipes

- [Deploy 3-node cluster](deploy-3-node-cluster.md)
- [Raft failover recovery](raft-failover-recovery.md)
- [Backup and restore](backup-and-restore.md)

## See also

- [Scaling runbook](../operations/runbooks/scaling.md)
- [Dragonboat storage](../storage/dragonboat.md)