# Lease management (W42-08)

Unified lease APIs for database and SSH dynamic credentials. See also [Day-2 operations](day2.md), [Database credentials](../deploy/database-credentials.md), and [Dynamic SSH credentials](../recipes/dynamic-ssh-credentials.md).

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

## Background renewal (W42-06)

The Raft leader renews expiring database and SSH leases on the cert-renew job interval. Trigger orchestrated renewal manually:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"db_grace":"24h","ssh_grace":"24h","pki_grace":"72h"}' \
  "$KNXVAULT_ADDR/sys/rotation/run"
```

Response includes `ssh_leases_renewed` alongside `db_leases_renewed` and `kv_rotated`.