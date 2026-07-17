<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: Orchestrated rotation

Run leader-coordinated rotation across KV, database, and PKI targets in one job.

## Trigger rotation

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

curl -s -X POST "$KNXVAULT_ADDR/sys/rotation/run" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{}' | jq .

# CLI
knxvault-cli sys rotation run
```

## What runs

The Raft leader executes configured rotators:

- KV paths with `sys/kv-rotation` schedules
- Database lease cleanup / rotation policies
- PKI `auto_renew` certificate renewal

## Monitor

```bash
# Leader logs
kubectl -n knxvault logs <leader-pod> --tail=100 | grep -i rotation

curl -s "$KNXVAULT_ADDR/audit/export?limit=20" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  | jq '.entries | map(select(.action|test("rotation")))'
```

## Related recipes

- [Secret rotation](secret-rotation.md)
- [Dynamic PostgreSQL credentials](dynamic-postgres-credentials.md)
- [PKI issue and revoke](pki-issue-and-revoke.md)

## See also

- [Day-2 operations](../operations/day2.md)