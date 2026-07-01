# Recipe: Seal and unseal

Emergency operator control to block all mutating API access while keeping health probes alive.

## When to seal

- Suspected compromise
- Maintenance requiring write freeze
- Key ceremony before master key rotation

## Seal

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

curl -s -X POST "$KNXVAULT_ADDR/sys/seal" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN"
```

While sealed:

- `POST /secrets/kv/*` → **503**
- `GET /health` → **200**
- Reads may also be blocked depending on seal implementation — test in your environment

## Unseal

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/unseal" \
  -H 'Content-Type: application/json' \
  -d '{"key":"'"$KNXVAULT_UNSEAL_KEY"'"}' | jq .
```

With Raft enabled, unseal key must differ from master key.

## Verify

```bash
knxvault-cli kv put seal/test value=ok   # should succeed after unseal
```

## Related recipes

- [Master key rotation](master-key-rotation.md)

## See also

- [Envelope encryption](../architecture/envelope-encryption.md)