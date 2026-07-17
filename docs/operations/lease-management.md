# Lease management (M-LEASE-1)

Unified lease lifecycle for dynamic secrets (database, SSH, and future engines).

## APIs

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| `GET` | `/sys/leases` | `sys/leases` read | List (filters: `engine`, `role`, `prefix`, `token_id`, `active_only`, `limit`, `offset`) |
| `GET` | `/sys/leases/:lease_id` | `sys/leases` read | Lookup |
| `POST` | `/sys/leases/renew` | `sys/leases` write | Body: `{"lease_id","ttl_seconds"}` |
| `POST` | `/sys/leases/revoke/:lease_id` | `sys/leases` write | Revoke one |
| `PUT` | `/sys/leases/revoke` | `sys/leases` write | Bulk by engine/role/path_prefix |
| `POST` | `/sys/leases/revoke-prefix` | `sys/leases` write | Body: `{"prefix"}` |
| `POST` | `/sys/leases/tidy` | `sys/leases` write | Force-revoke expired leases |

## Cascade revoke

When a client token is revoked (`DELETE /auth/token/self` or admin revoke), knxvault **cascades** to all active leases with matching `token_id` (when engines stamp the issuing token hash on the lease).

## Engine hooks

`LeaseService` registers:

- **database** / **ssh** — engine-specific revoke and renew  
- Other engines — repository mark-revoked if no hook registered  

New dynamic engines should call `RegisterRevoker` / `RegisterRenewer` and set `Lease.TokenID` on issue.

## Operations tips

- Monitor `knxvault_active_leases` (leader job).  
- After mass compromise: bulk revoke by `path_prefix` or tidy + rotate roles.  
- Tenant mode: prefer per-tenant path prefixes; lease ID tenant prefix is **W64-01** residual.

## Related

- [Vault-class capability plan](../design/vault-class-capability-plan.md) §6.1  
- Dynamic DB: [database-credentials.md](../deploy/database-credentials.md)  
