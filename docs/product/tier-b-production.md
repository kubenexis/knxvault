# Tier B Production Features (v0.4.5+)

This document covers Raft correctness, master key rotation, managed database credentials, dynamic membership, and seal/unseal shipped in the W36 Tier B–E backlog.

## Master key rotation (W36-17)

KNXVault uses a versioned **keyring** for envelope DEK wrapping. Existing secrets remain readable during rotation; a leader-only background job re-encrypts stored `DEKEnc` values.

| API | Permission | Description |
|-----|------------|-------------|
| `POST /sys/rotate-master-key` | `sys/rotate:write` | Accepts `{"new_key":"<base64 32-byte key>"}` |

CLI:

```bash
knxvault-cli sys rotate-master-key "$(openssl rand -base64 32)"
```

Configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_JOB_MASTER_KEY_REENCRYPT_INTERVAL` | `1m` | Leader job batch size 50 DEKs per tick |

## Managed database credentials (W36-18)

Roles with `execution_mode: managed` fetch admin credentials from KV (`admin_credentials_path`) and execute `creation_statements` / `revocation_statements` via `database/sql`. SQLite is bundled for tests; production MySQL/Postgres use **client** mode or add drivers.

Admin KV secret must include `connection_url` (e.g. `sqlite:/path/to.db`).

## Seal / unseal (W36-24)

Operational seal blocks mutating secured routes with `503 unavailable`. Reads and `POST /sys/unseal` remain available.

| API | Description |
|-----|-------------|
| `POST /sys/seal` | Seal vault (`sys/seal:write`) |
| `POST /sys/unseal` | Body `{"key":"<base64>"}` — **public** (no Bearer token required) |

| Variable | Description |
|----------|-------------|
| `KNXVAULT_UNSEAL_KEY` | Base64 unseal key; **required when Raft is enabled** and **must differ from master** (startup fails if unset or equal) |

CLI: `knxvault-cli sys seal`, `knxvault-cli sys unseal <key>`.

## Dynamic Raft membership (W36-23)

Leader-initiated membership changes via Dragonboat `SyncRequestAddNode` / `SyncRequestDeleteNode`:

| API | Permission | Body |
|-----|------------|------|
| `POST /sys/raft/add-node` | `sys/raft:write` | `{"node_id":4,"address":"host:63001"}` |
| `POST /sys/raft/remove-node` | `sys/raft:write` | `{"node_id":4}` |

See [`docs/operations/runbooks/scaling.md`](../operations/runbooks/scaling.md).

## Raft snapshots & backup (W36-06, W36-08)

- Dragonboat `SaveSnapshot` includes audit entries (`ExportSnapshot(true)`).
- `POST /sys/backup` uses atomic `snapshot.export` for a consistent cross-entity read.

Integration tests: `TestRaftLeaderFailover`, `TestIntegrationRaftSnapshotPreservesAudit`, `TestIntegrationRaftHTTPPKIRoundTrip`.