# Recipe: Rolling upgrade without downtime

Upgrade the KNXVault container image across a 3-node StatefulSet while maintaining quorum.

## Prerequisites

- [Backup](backup-and-restore.md) taken immediately before upgrade
- New image built and pushed
- Maintenance window for brief write blips if leader restarts

## Procedure

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

# 1. Pre-upgrade backup
knxvault-cli backup create -o pre-upgrade-$(date +%Y%m%d).json

# 2. Background write loop (optional — measure blip)
while true; do knxvault-cli kv put upgrade/ping value=$(date +%s); sleep 1; done &
LOOP_PID=$!

# 3. Update image
NEW_IMAGE=registry.example.com/knxvault:0.4.6
kubectl -n knxvault set image statefulset/knxvault knxvault="$NEW_IMAGE"

# 4. Rolling restart — highest ordinal first
for i in 2 1 0; do
  echo "Upgrading knxvault-$i"
  kubectl -n knxvault delete pod knxvault-$i --wait=true
  kubectl -n knxvault wait --for=condition=ready pod/knxvault-$i --timeout=300s
  curl -s $KNXVAULT_ADDR/ready | jq .
  sleep 10
done

kill $LOOP_PID 2>/dev/null

# 5. Post-upgrade smoke
knxvault-cli doctor
knxvault-cli kv put upgrade/done value=ok
curl -s $KNXVAULT_ADDR/metrics | grep knxvault_build_info
```

## Pass criteria

- ≥2 nodes healthy throughout
- Quorum never lost
- Write loop recovers automatically
- All pods report new `knxvault_build_info` version

## Rollback

```bash
kubectl -n knxvault set image statefulset/knxvault knxvault=registry.example.com/knxvault:0.5.1
# Repeat rolling restart
# Or restore from pre-upgrade backup if schema migration failed
```

## Related recipes

- [Backup and restore](backup-and-restore.md)
- [Deploy 3-node cluster](deploy-3-node-cluster.md)

## See also

- [Day-2 operations](../operations/day2.md)