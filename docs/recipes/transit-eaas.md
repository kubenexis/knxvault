# Recipe: Transit Encryption-as-a-Service (M-TRANSIT-1)

Encrypt application data without storing plaintext in knxvault KV.

## Create a key

```bash
curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
  "$KNXVAULT_ADDR/transit/keys/app-data"
```

## Encrypt / decrypt

```bash
curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"plaintext":"hello"}' \
  "$KNXVAULT_ADDR/transit/encrypt/app-data"
# → {"ciphertext":"v1:..."}

curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ciphertext":"v1:..."}' \
  "$KNXVAULT_ADDR/transit/decrypt/app-data"
```

## Rotate and rewrap

```bash
curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
  "$KNXVAULT_ADDR/transit/keys/app-data/rotate"

curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ciphertext":"v1:..."}' \
  "$KNXVAULT_ADDR/transit/rewrap/app-data"
```

## HMAC / verify (symmetric integrity — not asymmetric digital signatures)

`/transit/sign` is an **alias for HMAC** over the AES key material (W74-08). Prefer `/transit/hmac` in new code.

```bash
curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"input":"payload"}' "$KNXVAULT_ADDR/transit/hmac/app-data"

curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"input":"payload","signature":"hmac:v1:..."}' \
  "$KNXVAULT_ADDR/transit/verify/app-data"
```

Ciphertext is **bound to key name + version** (cannot decrypt under a different key name).

## RBAC paths

| Capability path | Ops |
|-----------------|-----|
| `transit/keys` | create, read, rotate |
| `transit/encrypt` | encrypt, rewrap |
| `transit/decrypt` | decrypt |
| `transit/sign` | sign, verify |
| `transit/hmac` | hmac |

Keys are envelope-encrypted at rest (same master key as KV/CA). Raw key material is never returned via API.
