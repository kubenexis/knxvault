# Shamir threshold unseal

> **Important:** Shamir applies to the **operational unseal key only**, not the envelope master key. See [ADR-0006](../adr/0006-seal-unseal-strategies.md).

## Configuration

| Variable | Description |
|----------|-------------|
| `KNXVAULT_UNSEAL_SCHEME` | `shamir` enables k-of-n shares |
| `KNXVAULT_UNSEAL_THRESHOLD` | Minimum shares required (e.g. `3`) |
| `KNXVAULT_UNSEAL_SHARES` | Total shares generated at init (e.g. `5`) |

When Shamir is enabled, the vault starts **sealed** and does not require `KNXVAULT_UNSEAL_KEY` at startup.

## Ceremony

```bash
# One-time split (stdout only — never store combined key in Raft)
knxvault-cli sys init-shamir "$(cat unseal.key | base64 -w0)" --shares 5 --threshold 3
```

Distribute shares to separate operators. Submit progressively:

```bash
curl -X POST /sys/unseal -d '{"key":"<base64-share>","share_id":1}'
```

Response includes `progress` and `threshold` until unsealed.

## Security notes

- Shares are never persisted server-side; progress resets on `POST /sys/seal`
- Master key custody remains via sealed Secrets / future KMS (**LT-14**)
- Pair with `mlock` hardening (**W41-01**) and sensitive buffer lifecycle (**W41-02**)