# Envelope Encryption

Technical reference for how KNXVault encrypts secrets, CA private keys, and backup archives at rest. Implementation lives in `internal/crypto/`; engines call `crypto.Service` **before** data is proposed to Raft (see [ADR-0004](../adr/0004-encrypt-before-replication.md)).

## Overview

KNXVault uses a **two-layer envelope**:

1. **Data layer** — a random 256-bit **data encryption key (DEK)** encrypts the payload (secret JSON, PEM private key, backup snapshot JSON).
2. **Key layer** — the 256-bit **master key** encrypts (wraps) the DEK.

Only ciphertext and wrapped DEKs are persisted. Raft logs, Pebble WAL entries, snapshots, and backup files never contain plaintext secrets or unwrapped DEKs.

```
┌─────────────────────────────────────────────────────────────┐
│  Plaintext payload (JSON / PEM)                             │
└───────────────────────────┬─────────────────────────────────┘
                            │ AES-256-GCM + random DEK
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  DataEnc  =  nonce ‖ ciphertext ‖ auth_tag                  │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────┴─────────────────────────────────┐
│  DEK (32 random bytes)                                      │
└───────────────────────────┬─────────────────────────────────┘
                            │ AES-256-GCM + master key (KeyRing)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  DEKEnc  =  [version byte]? ‖ nonce ‖ ciphertext ‖ tag      │
└─────────────────────────────────────────────────────────────┘
```

**Public API:** `crypto.Service.Seal` / `Open` (`internal/crypto/service.go`).

## Envelope encryption implementation

### Seal (encrypt)

`Seal(plaintext)` performs:

1. `GenerateDEK()` — 32 bytes from `crypto/rand`.
2. `EncryptWithDEK(dek, plaintext)` — AES-256-GCM over the payload.
3. `EncryptDEK(dek)` — wrap the DEK with the active master key via `KeyRing`.

Returns `(DataEnc, DEKEnc, err)`.

### Open (decrypt)

`Open(DataEnc, DEKEnc)` performs:

1. `DecryptDEK(DEKEnc)` — unwrap DEK using any known master key version.
2. `DecryptWithDEK(dek, DataEnc)` — decrypt payload.

### Where it is used

| Consumer | Fields | Code |
|----------|--------|------|
| KV secrets | `SecretVersion.DataEnc`, `DEKEnc` | `internal/engine/secrets/kvv2.go` |
| CA / issued keys | `CA.PrivateKeyEnc`, `DEKEnc` | `internal/engine/pki/engine.go` |
| Database dynamic creds | same as KV under `database/creds/...` | `internal/engine/secrets/database/engine.go` |
| Encrypted backups | `Archive.Ciphertext`, `DEKEnc` | `internal/backup/archive.go` |

Typical KV write path:

```go
payload, _ := json.Marshal(data)
dataEnc, dekEnc, err := crypto.Seal(payload)
// only dataEnc + dekEnc are proposed to Raft
```

## Key material (not key derivation)

KNXVault does **not** derive encryption keys from passphrases (no HKDF, PBKDF2, or Argon2 in the envelope path). Keys are either **loaded** or **randomly generated**.

| Key | Size | Source |
|-----|------|--------|
| **Master key** | 32 bytes (256 bits) | Operator-supplied, base64-decoded at startup |
| **DEK** | 32 bytes | `crypto/rand` per `Seal` / per CA key / per backup |
| **Unseal key** | 32 bytes | Separate operational key for seal/unseal (must differ from master key when Raft is enabled) |

The master key is used **directly** as the AES-256 key for DEK wrapping. Each DEK is used **directly** as the AES-256 key for payload encryption.

**Implication:** Choose a high-entropy master key (`openssl rand -base64 32`). There is no salt or iteration count to compensate for a weak passphrase.

## Authenticated encryption

All envelope operations use **AES-256-GCM** via Go `crypto/cipher`:

- **Cipher:** AES-256 (`aes.NewCipher` on 32-byte key).
- **Mode:** Galois/Counter Mode (GCM) — provides confidentiality and authenticity.
- **Additional authenticated data (AAD):** `nil` — no external context is bound into the tag; integrity covers `nonce ‖ ciphertext` only.
- **Authentication tag:** Appended by `gcm.Seal`; verified on `gcm.Open` (decryption fails if ciphertext or tag is tampered).

Implementation: `internal/crypto/envelope.go`.

Tampering with `DataEnc` or `DEKEnc` in Raft storage or backups causes `Open` to return an error; there is no silent corruption.

## Nonce handling

GCM requires a unique nonce per encryption under the same key. KNXVault handles this as follows.

### Generation

On each `Envelope.Encrypt`:

1. Build AES-GCM with the 32-byte key.
2. Allocate `nonce := make([]byte, gcm.NonceSize())` (12 bytes on Go’s standard GCM).
3. Fill with `crypto/rand` (`io.ReadFull(rand.Reader, nonce)`).
4. `gcm.Seal(nonce, nonce, plaintext, nil)` — prepends the nonce to the output.

### On-disk layout

```
DataEnc / DEKEnc inner blob (after optional version prefix):
┌──────────────┬─────────────────────┬──────────┐
│ nonce (12 B) │ ciphertext          │ tag      │
└──────────────┴─────────────────────┴──────────┘
```

`Decrypt` splits `nonce = blob[:12]`, `enc = blob[12:]`, then `gcm.Open`.

### Uniqueness guarantees

| Layer | Key changes when | Nonce |
|-------|------------------|-------|
| Payload (`DataEnc`) | New DEK per object version / backup | Fresh random nonce per encryption |
| DEK wrap (`DEKEnc`) | Master key version on re-wrap | Fresh random nonce per `EncryptDEK` |

A new secret version always gets a new DEK, so nonce reuse under one DEK is limited to a single `Encrypt` call.

## Master key storage

### Loading at startup

`internal/crypto/masterkey/loader.go` reads the master key once during `app.NewDependencies`:

| Priority | Source | Format |
|----------|--------|--------|
| 1 | `KNXVAULT_MASTER_KEY_FILE` | Absolute path to a file containing base64 (whitespace-trimmed) |
| 2 | `KNXVAULT_MASTER_KEY` | Base64-encoded 32-byte key |

Validation:

- Decoded length must be exactly **32 bytes**.
- File path must be **absolute**, must not contain `..`, and must refer to a regular file (opened via `os.OpenRoot` for path confinement).

### In-process lifetime

After load:

- `Dependencies.Crypto` — `*crypto.Service` with an in-memory `KeyRing`.
- `Dependencies.MasterKey` — copy of the raw key bytes (used for fingerprinting / unseal resolution only in deps wiring).

The master key is **never**:

- Written to Raft or audit logs.
- Returned by API responses.
- Logged at startup.

When Raft is enabled, startup **fails** without a master key (`internal/app/deps.go`). In-memory dev mode (Raft disabled) may run without encryption, with a warning.

### Operator storage patterns

| Pattern | Notes |
|---------|-------|
| Kubernetes Secret | Mount as file → `KNXVAULT_MASTER_KEY_FILE=/var/run/secrets/knxvault/master.key` (recommended) |
| Environment variable | `KNXVAULT_MASTER_KEY` — simpler for dev; avoid in production manifest repos |
| External KMS / HSM | **Not implemented** — future LT/HSM work; today the process needs the raw 32-byte key in memory |

Use a **separate** `KNXVAULT_UNSEAL_KEY` in production (required when Raft is enabled; must not equal the master key). Unseal controls operational seal state; it is not used for envelope encryption.

### Sensitive material zeroing

Decrypted CA private keys are zeroed after use with `memzero.Bytes` in the PKI engine (`internal/crypto/memzero`). DEKs and master key material are not systematically zeroed on every `Open` — rely on process isolation and short-lived in-memory use.

## Key rotation logic

Master key rotation re-wraps DEKs; it does **not** re-encrypt `DataEnc` payloads (the per-object DEK bytes stay the same).

### KeyRing (`internal/crypto/keyring.go`)

- Holds `map[byte][]byte` of master key **versions** (1, 2, 3, …).
- **Active version** — used for new `EncryptDEK` calls.
- **Legacy mode** — when only version 1 exists, `DEKEnc` omits the 1-byte version prefix. After the first rotation, new wraps prefix with the active version byte.

`DecryptDEK` tries, in order:

1. **Versioned path** — if `len(enc) ≥ 46` and byte 0 is a known version and `enc[1:]` decrypts to a 32-byte DEK.
2. **Legacy fallback** — try each known master key against the full blob (pre-rotation format).

### Rotate API

| Step | Component | Behavior |
|------|-----------|----------|
| 1 | `POST /sys/rotate-master-key` | Body `{"new_key":"<base64 32-byte>"}` → `crypto.RotateMasterKey` adds next version and sets active |
| 2 | Leader job | `JobRunner.runMasterKeyReencrypt` every `KNXVAULT_JOB_MASTER_KEY_REENCRYPT_INTERVAL` (default `1m`) |
| 3 | `MasterKeyService.ReencryptDEKs` | Batch (50 items/tick): for each CA and secret with `DEKNeedsReencrypt`, `ReencryptDEK` + persist updated `DEKEnc` |

CLI: `knxvault-cli sys rotate-master-key "$(openssl rand -base64 32)"`.

During transition, **old master key versions remain in memory** until process restart — all versions are needed to decrypt existing `DEKEnc` until re-encryption completes. New encryptions use the active version immediately.

`DEKNeedsReencrypt` treats blobs as versioned only when the version prefix decrypts successfully (avoids false negatives on legacy ciphertext whose first byte coincidentally matches a version number).

### What rotation does not do

- Does not rotate the key in `KNXVAULT_MASTER_KEY` env / mounted file — operators must update the Secret and restart nodes with the new key material coordinated with the API call.
- Does not re-encrypt `DataEnc` — only `DEKEnc` is re-wrapped.
- Is not persisted across restarts — the in-memory `KeyRing` is rebuilt from the single key loaded at startup unless rotation is invoked again. **Production note:** after rotation, all replicas need the new master key available and should receive the same rotation API call (or share state via your runbook); the version map is per-process.

See [Tier B production features](../product/tier-b-production.md) for API permissions and job tuning.

## Persisted field reference

| Field | Contents |
|-------|----------|
| `data_enc` / `DataEnc` | `nonce (12) ‖ AES-GCM ciphertext ‖ tag` |
| `dek_enc` / `DEKEnc` | Optional `version (1)` + same GCM layout wrapping the 32-byte DEK |
| `private_key_enc` | Same as `DataEnc` (PKI PEM bytes) |

Backup archive (`format: knxvault-backup`):

```json
{
  "format": "knxvault-backup",
  "version": 1,
  "ciphertext": "<DataEnc of full snapshot JSON>",
  "dek_enc": "<DEKEnc>"
}
```

## Code map

| File | Responsibility |
|------|----------------|
| `internal/crypto/envelope.go` | AES-256-GCM encrypt/decrypt, nonce prepend |
| `internal/crypto/service.go` | `Seal` / `Open`, DEK generation, KeyRing facade |
| `internal/crypto/keyring.go` | Master key versions, DEK wrap/unwrap, rotation helpers |
| `internal/crypto/masterkey/loader.go` | Master key load from env/file |
| `internal/service/masterkey.go` | Rotation API + batch DEK re-encrypt |
| `internal/app/jobs.go` | Leader-only re-encrypt ticker |
| `internal/crypto/memzero/memzero.go` | Zero CA key material after use |

## Related documents

- [ADR-0003: Envelope encryption](../adr/0003-envelope-encryption.md) — design decision
- [ADR-0004: Encrypt before replication](../adr/0004-encrypt-before-replication.md) — Raft invariant
- [Security model](security-model.md) — threat model and auth
- [Data models](data-models.md) — `DataEnc` / `DEKEnc` fields
- [Configuration reference](../installation/configuration.md) — `KNXVAULT_MASTER_KEY_*`
- [Backup & restore](../deploy/backup-restore.md) — encrypted archive format