<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: Raft failover recovery

Recover from leader loss and verify continued availability.

## When to use

- Leader pod crashed or was deleted
- Suspected quorum issues after network partition
- Post-maintenance health check

## Procedure

### 1. Identify current leader

```bash
for i in 0 1 2; do
  echo -n "knxvault-$i: "
  kubectl -n knxvault exec knxvault-$i -- wget -qO- http://localhost:8200/ready 2>/dev/null | jq -c '{leader,raft_ready}'
done
```

### 2. Kill leader (chaos test)

```bash
LEADER_POD=knxvault-1   # adjust
kubectl -n knxvault delete pod $LEADER_POD --wait=false
```

### 3. Monitor failover

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
watch -n2 'curl -s $KNXVAULT_ADDR/ready | jq .'
```

Expect new leader within 10–60 seconds.

### 4. Verify writes resume

```bash
knxvault-cli kv put failover/test value=$(date +%s)
knxvault-cli kv get failover/test --show-secrets
```

### 5. Confirm single leader in metrics

```bash
for i in 0 1 2; do
  kubectl -n knxvault exec knxvault-$i -- wget -qO- http://localhost:8200/metrics 2>/dev/null \
    | grep knxvault_raft_leader
done
```

## Quorum loss

If 2 of 3 nodes are unreachable:

- Writes fail (no majority)
- Vault stays **unsealed** (no auto-seal)
- Heal network; Raft catches up automatically

See [Manual testing MT-01](../engineering/manual-testing-strategy.md).

## Automated chaos script

```bash
./test/chaos/raft-pod-kill.sh
```

## Related recipes

- [Deploy 3-node cluster](deploy-3-node-cluster.md)
- [Add and remove Raft nodes](raft-add-remove-node.md)

## See also

- [Raft failover runbook](../operations/runbooks/raft-failover.md)