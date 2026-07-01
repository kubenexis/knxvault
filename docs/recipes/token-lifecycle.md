# Recipe: Token lifecycle

Create, renew, and revoke scoped client tokens for applications and operators.

## Create token from role

```bash
export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=<admin-token>

curl -s -X POST "$KNXVAULT_ADDR/auth/token/create" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "role": "app-reader",
    "ttl": "8h",
    "renewable": true
  }' | jq .

export CLIENT_TOKEN=<client_token>
```

## Validate token

```bash
curl -s -X POST "$KNXVAULT_ADDR/auth/token" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$CLIENT_TOKEN\"}" | jq .
```

## Renew

```bash
curl -s -X POST "$KNXVAULT_ADDR/auth/token/renew" \
  -H "Authorization: Bearer $CLIENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ttl":"8h"}' | jq .
```

## Revoke (self)

```bash
curl -s -X DELETE "$KNXVAULT_ADDR/auth/token/self" \
  -H "Authorization: Bearer $CLIENT_TOKEN"
```

## Agent delegation

For advanced automation:

```bash
curl -s -X POST "$KNXVAULT_ADDR/auth/agent/delegate" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role":"ci-deploy","ttl":"1h"}' | jq .
```

## Best practices

| Practice | Reason |
|----------|--------|
| Short TTL | Limits blast radius |
| `renewable: true` | Apps can extend without re-auth |
| One role per workload | Easier audit and revocation |
| Never use root in apps | Full admin exposure |

## Related recipes

- [RBAC policies](rbac-policies.md)
- [Kubernetes ServiceAccount auth](kubernetes-serviceaccount-auth.md)

## See also

- [CLI reference](../cli/reference.md)