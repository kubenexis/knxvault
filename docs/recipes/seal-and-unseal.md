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

## Unseal (single key)

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/unseal" \
  -H 'Content-Type: application/json' \
  -d '{"key":"'"$KNXVAULT_UNSEAL_KEY"'"}' | jq .
```

With Raft enabled, **`KNXVAULT_UNSEAL_KEY` is required at process start** and **must differ from the master key**. Startup fails with `unseal key is required when raft is enabled` if it is unset. Store unseal with the same custody as master ([operator security](../operations/operator-security.md#5-master-key-and-unseal-key-custody)).

## Multi-share unseal (Shamir)

When `KNXVAULT_UNSEAL_THRESHOLD` is greater than 1, the process still holds the full unseal secret in memory (configured at start), but operators submit **t** distinct Shamir shares instead of the full key.

1. **Split offline** (admin, requires `sys/seal` write) — distribute shares to custodians:

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/generate-unseal-shares" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"key":"'"$KNXVAULT_UNSEAL_KEY"'","shares":5,"threshold":3}' | jq .
# → {"shares":["base64..."],"threshold":3}
```

2. **Submit shares** until progress reaches the threshold:

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/unseal" \
  -H 'Content-Type: application/json' \
  -d '{"share":"'"$SHARE_B64"'"}' | jq .
# → {"sealed":true,"progress":1,"threshold":3} until unsealed
```

Failed share combinations clear pending shares and apply progressive unseal backoff (Retry-After). The durable `seal.state` marker **never** auto-unseals (W52-01).

## Verify

```bash
curl -s "$KNXVAULT_ADDR/ready" | jq .   # sealed:false
knxvault-cli doctor --json              # server.sealed ok
knxvault-cli kv put seal/test value=ok  # should succeed after unseal
knxvault-cli kv get seal/test --show-secrets
```

## Related recipes

- [Master key rotation](master-key-rotation.md)
- [Deploy 3-node cluster](deploy-3-node-cluster.md)

## See also

- [Envelope encryption](../architecture/envelope-encryption.md)
- [Installation guide](../installation/install.md)
- [Configuration reference](../installation/configuration.md)