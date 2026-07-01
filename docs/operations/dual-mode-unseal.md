# Dual-mode seal (auto-unseal + Shamir break-glass)

Implements **W41-14** per [ADR-0006](../adr/0006-seal-unseal-strategies.md). Cloud KMS auto-unseal (**LT-14**) is long-term; a **file** stub supports development and air-gap rehearsals.

## Configuration matrix

| Mode | Variables | Behavior |
|------|-----------|----------|
| Single key | `KNXVAULT_UNSEAL_KEY` | Default; unsealed at startup when key matches |
| Shamir | `KNXVAULT_UNSEAL_SCHEME=shamir`, threshold/shares | Starts sealed; shares via `POST /sys/unseal` |
| Auto-unseal | `KNXVAULT_AUTO_UNSEAL_PROVIDER=file`, `KNXVAULT_AUTO_UNSEAL_KEY_FILE` | Startup reads unseal key from file |
| Break-glass | `KNXVAULT_BREAK_GLASS_SHAMIR=true` + auto-unseal | KMS/file first; Shamir shares if auto-unseal fails |

## Precedence at startup

1. Attempt auto-unseal provider (increments `knxvault_auto_unseal_success_total`)
2. If sealed and Shamir enabled, wait for shares (increments `knxvault_shamir_unseal_total`)
3. Manual `POST /sys/seal` clears Shamir progress

## Failure modes

| Scenario | Result |
|----------|--------|
| KMS/file unavailable | Vault stays sealed; operators use Shamir |
| Wrong share | `400 invalid unseal share`; rate limit applies |
| Master key missing | Startup fails (independent of unseal mode) |

Full cloud KMS integration ships with **LT-14**; this document covers config stubs and operator workflow until then.