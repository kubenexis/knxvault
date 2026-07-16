# Recipe: Seal and unseal

Emergency operator control to block mutating (and, when seal-guarded, secret-bearing) API access while keeping health probes alive.

## When to seal

- Suspected compromise
- Maintenance requiring write freeze
- Key ceremony before master key rotation

## Start-sealed behavior

| Situation | Behavior |
|-----------|----------|
| `KNXVAULT_UNSEAL_KEY` set | Process **starts sealed**; only cryptographic unseal opens the data plane |
| Raft enabled | Unseal key **required** at start and **must differ** from master |
| Unseal key unset (non-Raft) | Unseal material falls back to master key — process still starts sealed |
| Durable `seal.state` file | May record sealed/unsealed for operators; **never** auto-unseals (W52-01) |

Do not expect writes (KV, PKI, AppRole register, operator vault-mode CA create) to succeed until unseal completes.

## Seal

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

curl -s -X POST "$KNXVAULT_ADDR/sys/seal" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN"
```

While sealed:

- Mutating secured routes → **503** (`unavailable: vault is sealed`)
- `GET /health` / `GET /ready` → **200** (may report `"sealed":true`)
- `POST /sys/unseal` remains available (rate limited)

## Unseal (single key)

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/unseal" \
  -H 'Content-Type: application/json' \
  -d '{"key":"'"$KNXVAULT_UNSEAL_KEY"'"}' | jq .
# → {"sealed":false}
```

`$KNXVAULT_UNSEAL_KEY` is the **base64 encoding of the raw 32-byte secret** (same value as the env var). Store with the same custody as master ([operator security](../operations/operator-security.md#5-master-key-and-unseal-key-custody)).

## Multi-share unseal (Shamir)

Set `KNXVAULT_UNSEAL_THRESHOLD=t` (`t>1`). The process still loads the full unseal secret from env at start; operators open the vault by submitting **t** distinct shares instead of the full key.

### Split shares

**While sealed**, `POST /sys/generate-unseal-shares` is **blocked** (SealGuard). Prefer offline split before/after downtime, or split while temporarily unsealed.

**Offline (ops / lab):**

```bash
# Same package as server combine
go run ./scripts/shamir-split -key "$KNXVAULT_UNSEAL_KEY" -n 5 -t 3
# → one base64 share per line; distribute to custodians
```

**Admin API (vault unsealed, requires `sys/seal` write):**

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/generate-unseal-shares" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"key":"'"$KNXVAULT_UNSEAL_KEY"'","shares":5,"threshold":3}' | jq .
# → {"shares":["base64..."],"threshold":3}
```

### Submit shares

```bash
curl -s -X POST "$KNXVAULT_ADDR/sys/unseal" \
  -H 'Content-Type: application/json' \
  -d '{"share":"'"$SHARE_B64"'"}' | jq .
# → {"sealed":true,"progress":1,"threshold":3} until unsealed
# → {"sealed":false,"progress":3,"threshold":3} when open
```

Any **t** distinct shares recover the secret (e.g. shares 1+3 if threshold is 2). Failed combinations clear pending shares and apply progressive backoff (`Retry-After`).

Config: `KNXVAULT_UNSEAL_THRESHOLD` — see [configuration](../installation/configuration.md).

## Verify

```bash
curl -s "$KNXVAULT_ADDR/health" | jq '.sealed'   # false
curl -s "$KNXVAULT_ADDR/ready" | jq .
knxvault-cli doctor --json                       # server.sealed ok, fail=0
knxvault-cli kv put seal/test value=ok
knxvault-cli kv get seal/test --show-secrets
```

## Automated coverage

| Layer | What is proven |
|-------|----------------|
| Unit | `internal/crypto/shamir`, `SealState.SubmitShare` |
| Integration | `TestE2EMultiShareUnsealHTTP`, seal HTTP tests; daemon auto-unseal |
| Lab full E2E | Start sealed → offline 3-of-2 shares → data plane; re-seal + shares 1+3 (**53/53**) |

Details: [E2E and lab tests](../engineering/e2e-and-lab-tests.md), [lab-full-e2e.md](../engineering/lab-full-e2e.md).  
Re-run lab: `make lab-full-e2e`.

## Related recipes

- [Master key rotation](master-key-rotation.md)
- [Deploy 3-node cluster](deploy-3-node-cluster.md)

## See also

- [Envelope encryption](../architecture/envelope-encryption.md)
- [Operator security](../operations/operator-security.md)
- [Installation guide](../installation/install.md)
- [Configuration reference](../installation/configuration.md)
- [W53 residual features](../audit/formal-w53-residual-features-2026-07-16.md)
