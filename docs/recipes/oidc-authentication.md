# Recipe: OIDC authentication

Authenticate human users and machine workloads using JWTs from a corporate identity provider.

## What you will learn

- Configuring an OIDC-backed KNXVault role
- `POST /auth/oidc/:role` login flow
- Machine identity tracking for non-human principals

## Prerequisites

- OIDC provider (Keycloak, Azure AD, Okta, Google Workspace, etc.)
- Issuer URL, audience, and JWKS endpoint
- Admin token for role configuration

## Concepts

| Field | Purpose |
|-------|---------|
| `issuer` (`iss`) | Must match IdP issuer claim |
| `audience` (`aud`) | Must match token audience configured for KNXVault |
| `jwks_url` | IdP public keys for signature verification |
| `max_ttl_seconds` | Upper bound on issued client token lifetime |

## Step 1 — Register KNXVault in your IdP

Create an OIDC client (or API resource) with:

- **Redirect URIs** — if using browser flow (optional for API JWT exchange)
- **Audience** — e.g. `knxvault` or your API identifier
- **Scopes** — `openid`, `profile`, `email` (minimum)

Note the issuer URL and JWKS URL:

```text
Issuer:  https://idp.example.com/realms/corp
JWKS:    https://idp.example.com/realms/corp/protocol/openid-connect/certs
```

## Step 2 — Create policy for OIDC users

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

curl -s -X PUT "$KNXVAULT_ADDR/sys/policies/oidc-developer" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "paths": {
      "secrets/kv/dev/*": {"capabilities": ["create", "read", "update", "delete"]},
      "sys/capabilities": {"capabilities": ["read"]}
    }
  }'
```

## Step 3 — Create OIDC role

```bash
curl -s -X PUT "$KNXVAULT_ADDR/sys/roles/oidc-developer" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "policies": ["oidc-developer"],
    "auth_method": "oidc",
    "oidc": {
      "issuer": "https://idp.example.com/realms/corp",
      "audience": "knxvault",
      "jwks_url": "https://idp.example.com/realms/corp/protocol/openid-connect/certs",
      "max_ttl_seconds": 3600
    }
  }'
```

> If your KNXVault build does not yet accept the `oidc` block on `PUT /sys/roles`, configure via the supported API surface or consult [backlog W43-06](../backlog.md) for the current workaround.

## Step 4 — Obtain an IdP JWT

**Client credentials (automation):**

```bash
OIDC_JWT=$(curl -s -X POST "https://idp.example.com/realms/corp/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=knxvault-ci" \
  -d "client_secret=$CLIENT_SECRET" | jq -r .access_token)
```

**Browser / device code** — use your IdP's standard login; copy the access token.

## Step 5 — Login to KNXVault

```bash
curl -s -X POST "$KNXVAULT_ADDR/auth/oidc/oidc-developer" \
  -H 'Content-Type: application/json' \
  -d "{\"jwt\":\"$OIDC_JWT\"}" | jq .

export KNXVAULT_TOKEN=$(curl -s -X POST "$KNXVAULT_ADDR/auth/oidc/oidc-developer" \
  -H 'Content-Type: application/json' \
  -d "{\"jwt\":\"$OIDC_JWT\"}" | jq -r '.data.token // .token')
```

## Step 6 — Use scoped token

```bash
knxvault-cli kv put dev/app/config value=from-oidc-user
knxvault-cli kv get dev/app/config --show-secrets
```

## Step 7 — List machine identities

OIDC logins for automation create machine identity records:

```bash
curl -s "$KNXVAULT_ADDR/sys/machine-identities" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

Revoke compromised identities:

```bash
curl -s -X DELETE "$KNXVAULT_ADDR/sys/machine-identities/<id>" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Negative tests

| Test | Expected |
|------|----------|
| Expired JWT | `401` |
| Wrong `aud` | `401` / `403` |
| Wrong `iss` | `401` |
| Valid JWT, wrong role name | `403` |

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| JWKS fetch failure | Network egress from KNXVault to IdP; check `jwks_url` |
| Clock skew | Sync NTP on nodes |
| Role API rejects `oidc` block | Upgrade or use documented workaround (W43-06) |

## Related recipes

- [RBAC policies](rbac-policies.md)
- [Token lifecycle](token-lifecycle.md)
- [Audit export](audit-export.md)

## See also

- [API reference — auth](../api/reference.md)
- [Security model](../architecture/security-model.md)