# OIDC group and claim → policy mapping

**W41-07** extends role OIDC configuration with dynamic policy assignment from IdP claims.

## Role configuration

```json
{
  "name": "entra-admins",
  "policies": ["default"],
  "auth_method": "oidc",
  "oidc": {
    "issuer": "https://login.microsoftonline.com/<tenant>/v2.0",
    "audience": "<app-id>",
    "jwks_url": "https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys",
    "claim_mappings": [
      {
        "claim": "groups",
        "match": "<vault-admins-group-id>",
        "policies": ["admin"]
      }
    ],
    "bound_claims": {
      "tid": "<tenant-id>"
    }
  }
}
```

## Behavior

- Claim mappings are evaluated after JWT signature validation
- `groups` arrays and string claims are supported
- `regex: true` enables pattern matching on claim values
- Mapped policies are unioned with role default policies
- When mappings are configured but none match → `403 Forbidden`

## Okta example

```json
"claim_mappings": [
  {"claim": "groups", "match": "Vault Operators", "policies": ["ops"]}
]
```

Update roles via `PUT /sys/roles/:name`.