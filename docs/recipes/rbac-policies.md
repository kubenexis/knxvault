<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: RBAC policies and roles

Define least-privilege access with policies and bind them to tokens, ServiceAccounts, or OIDC users.

## What you will learn

- Policy document structure (`paths` + `capabilities`)
- Creating roles and issuing scoped tokens
- Allow vs deny semantics
- Checking effective capabilities

## Prerequisites

- Admin token
- Understanding of your secret path layout (e.g. `app/`, `team-a/`)

## Concepts

```
Policy (what is allowed)  +  Role (who gets it)  →  Client token
```

| Object | Stored at | Purpose |
|--------|-----------|---------|
| **Policy** | `sys/policies/:name` | Path patterns + capabilities |
| **Role** | `sys/roles/:name` | Policy list + auth bindings (SA, OIDC) |
| **Token** | Ephemeral | Bearer credential for API calls |

**Capabilities:** `create`, `read`, `update`, `delete`, `list`, `deny`, `sudo` (admin paths).

## Step 1 — Reader policy

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

curl -s -X PUT "$KNXVAULT_ADDR/sys/policies/app-reader" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "paths": {
      "secrets/kv/app/*": {"capabilities": ["read", "list"]},
      "inject/render": {"capabilities": ["read"]}
    }
  }'
```

Alternative compact format (also supported):

```json
{
  "effect": "allow",
  "resources": ["secrets/kv/app/*"],
  "actions": ["read", "list"]
}
```

## Step 2 — Writer policy (narrow)

```bash
curl -s -X PUT "$KNXVAULT_ADDR/sys/policies/app-writer" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "paths": {
      "secrets/kv/app/*": {"capabilities": ["create", "read", "update"]}
    }
  }'
```

## Step 3 — Deny admin paths

```bash
curl -s -X PUT "$KNXVAULT_ADDR/sys/policies/deny-sys" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "paths": {
      "sys/*": {"capabilities": ["deny"]}
    }
  }'
```

Attach `deny-sys` to every non-admin role.

## Step 4 — Database and PKI policies

```bash
# Database creds generator
curl -s -X PUT "$KNXVAULT_ADDR/sys/policies/db-creds" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "paths": {
      "secrets/database/creds/*": {"capabilities": ["create", "read"]},
      "secrets/database/renew/*": {"capabilities": ["update"]}
    }
  }'

# PKI issuer
curl -s -X PUT "$KNXVAULT_ADDR/sys/policies/pki-issuer" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "paths": {
      "pki/*": {"capabilities": ["create", "read"]}
    }
  }'
```

## Step 5 — Create a role

**For token-based apps:**

```bash
curl -s -X PUT "$KNXVAULT_ADDR/sys/roles/ci-deploy" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "policies": ["app-writer", "deny-sys"]
  }'
```

**For Kubernetes ServiceAccounts:**

```bash
curl -s -X PUT "$KNXVAULT_ADDR/sys/roles/app-sa" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "policies": ["app-reader", "deny-sys"],
    "bound_service_account_names": ["my-app"],
    "bound_service_account_namespaces": ["production"]
  }'
```

## Step 6 — Issue a scoped token

```bash
curl -s -X POST "$KNXVAULT_ADDR/auth/token/create" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "role": "ci-deploy",
    "ttl": "1h",
    "renewable": true
  }' | jq .

export SCOPED_TOKEN=<client_token_from_response>
```

## Step 7 — Test enforcement

```bash
# Allowed read
curl -s -o /dev/null -w "%{http_code}\n" \
  "$KNXVAULT_ADDR/secrets/kv/app/config" \
  -H "Authorization: Bearer $SCOPED_TOKEN"

# Denied sys admin
curl -s -o /dev/null -w "%{http_code}\n" \
  -X GET "$KNXVAULT_ADDR/sys/policies" \
  -H "Authorization: Bearer $SCOPED_TOKEN"
```

## Step 8 — Check capabilities

```bash
curl -s "$KNXVAULT_ADDR/sys/capabilities" \
  -H "Authorization: Bearer $SCOPED_TOKEN" | jq .
```

## Policy design patterns

| Pattern | Example |
|---------|---------|
| **Per-team prefix** | `secrets/kv/team-a/*` read for team A role |
| **CI write-only** | `create` + `update` on `secrets/kv/ci/*`; no `delete` |
| **Injector only** | `inject/render` read; no direct KV |
| **Break-glass admin** | Separate admin role; MFA at IdP; short TTL |

> **Note:** Path-level ACL granularity for arbitrary prefixes is improving (backlog W41-01). Current enforcement is route-coarse for some engines — test with `sys/capabilities` before production rollout.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `403` on expected path | Policy path pattern mismatch; check trailing `*` |
| Deny not blocking | Ensure deny policy attached to same role |
| SA auth works but wrong paths | Role policies — not K8s RBAC |

## Related recipes

- [Kubernetes ServiceAccount auth](kubernetes-serviceaccount-auth.md)
- [OIDC authentication](oidc-authentication.md)
- [Token lifecycle](token-lifecycle.md)

## See also

- [Security model](../architecture/security-model.md)
- [Getting started §4](../user/getting-started.md)