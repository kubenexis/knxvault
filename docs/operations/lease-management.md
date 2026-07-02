# Lease management (W42-08)

Unified lease APIs for database and SSH dynamic credentials.

## Lookup

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$KNXVAULT_ADDR/sys/leases/$LEASE_ID"
```

## List with filters

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$KNXVAULT_ADDR/sys/leases?engine=database&role=readonly&active_only=true"
```

CLI: `knxvault-cli sys leases list --engine database`

## Bulk revoke (incident playbook)

When a role is compromised, revoke all active leases:

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -d '{"engine":"database","role":"compromised-role"}' \
  "$KNXVAULT_ADDR/sys/leases/revoke"
```

## Role tuning (W42-04)

Database/SSH roles support `default_ttl`, `max_ttl`, `renewable`, `period`, `max_leases`.

## Warnings (W42-05)

Renew responses may include `warnings[]` when remaining TTL is below 10% of max.