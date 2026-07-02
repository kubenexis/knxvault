# Policy engine (W41-07)

KNXVault RBAC uses **default deny** with path-aware capabilities aligned to Vault/OpenBao semantics.

## Resource naming

| Prefix | Example | Notes |
|--------|---------|-------|
| `secrets/kv/<path>` | `secrets/kv/team-a/app` | KVv2 logical path |
| `secrets/database/...` | roles, creds | Dynamic DB engine |
| `pki/...` | issue, ca | PKI operations |
| `sys/policies` | policy CRUD | Admin |
| `sys/leases` | lease lookup/list/revoke | Unified leasing |

## Capabilities (W41-02)

| Capability | HTTP mapping |
|------------|--------------|
| `read` | GET secret values, PKI read |
| `list` | KV metadata, list, versions |
| `write` | POST/PUT mutations |
| `delete` | DELETE KV versions |
| `sudo` | `POST /auth/token/create` |

Policies accept `capabilities[]` (preferred) or legacy `actions[]`.

## Deny precedence (W41-03)

Explicit **deny** policies override allow within the evaluated policy set. No implicit allow except bootstrap defaults (`admin`, etc.).

## Glob patterns (W41-09)

Supported: `*`, `?`, `**` in path segments. Example: `secrets/kv/team-?/app-*`.

## Policy composition (W41-10)

Roles may reference `policy_groups` / policy `includes[]`. Policies are flattened at evaluation time; deny in any module wins.

## Simulation (W41-04)

```bash
knxvault-cli sys policy simulate --policies team-a-kv --resource secrets/kv/team-a/x --capability read
```

## Migration from `secrets-reader`

Replace coarse `secrets/*` + `read` with path-scoped policies:

```json
{
  "effect": "allow",
  "resources": ["secrets/kv/team-a/*"],
  "capabilities": ["read", "list"]
}
```