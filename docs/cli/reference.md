# CLI Reference

The `knxvault-cli` binary provides Day-0 and Day-2 operations against the KNXVault REST API.

It is a **host/native HTTP client**. It does **not** discover Docker/containerd instances; set `--addr` / `KNXVAULT_ADDR` (default `http://localhost:8200`) to the published API. End-to-end standalone story: [Standalone distroless + host CLI](../operations/standalone-distroless-day0-day2.md).

## Installation

```bash
make build-cli
```

Binary: `bin/knxvault-cli`

## Configuration

Precedence: **flags → `~/.knxvault/config.yaml` → environment variables**.

| Flag / env / file | Default | Description |
|-------------------|---------|-------------|
| `--addr` / `KNXVAULT_ADDR` / `addr` in config | `http://localhost:8200` | API base URL |
| `--token` / `KNXVAULT_TOKEN` / `token` in config | _(empty)_ | Bearer client token |

Example `~/.knxvault/config.yaml`:

```yaml
addr: http://localhost:8200
token: dev-root-token
```

## Commands

| Command | Description |
|---------|-------------|
| `doctor [--json]` | Diagnose deployment health and CLI configuration |
| `health` | `GET /health` |
| `status` | `GET /ready` |
| `auth login [--token]` | `POST /auth/token` |
| `kv get <path> [--show-secrets]` | Read a KV secret (values **`[REDACTED]`** by default; stderr hints to use `--show-secrets`) |
| `kv put <path> key=value...` | Write a KV secret |
| `pki root --name --common-name [--ttl] [--key-bits]` | Create a self-signed root CA |
| `pki issue --role --common-name [--dns] [--ttl] [--auto-renew]` | Issue a leaf certificate |
| `pki revoke --ca-id --serial [--reason]` | `POST /pki/revoke` |
| `pki renew --ca-id --serial [--ttl]` | `POST /pki/renew` |
| `sys policies list` | `GET /sys/policies` |
| `sys policies get <name>` | `GET /sys/policies/:name` |
| `sys policies put <name> <json-file>` | `PUT /sys/policies/:name` |
| `sys policies delete <name>` | `DELETE /sys/policies/:name` |
| `sys roles list` | `GET /sys/roles` |
| `sys roles get <name>` | `GET /sys/roles/:name` |
| `sys roles put <name> <json-file>` | `PUT /sys/roles/:name` |
| `sys roles delete <name>` | `DELETE /sys/roles/:name` |
| `sys rotate-master-key <base64-key>` | `POST /sys/rotate-master-key` |
| `sys rotation-run [--db-grace] [--pki-grace]` | `POST /sys/rotation/run` |
| `sys raft-add-node <id> <address>` | `POST /sys/raft/add-node` |
| `sys raft-remove-node <id>` | `POST /sys/raft/remove-node` |
| `sys issue-listener-tls` | `POST /sys/tls/issue-listener` |
| `sys seal` | `POST /sys/seal` |
| `sys unseal <base64-key>` | `POST /sys/unseal` with full key (multi-share uses HTTP `{"share":…}` — see [seal recipe](../recipes/seal-and-unseal.md)) |
| `audit export [--limit]` | `GET /audit/export` |
| `database roles put <name> <json-file>` | `PUT /secrets/database/roles/:name` |
| `database roles get <name>` | `GET /secrets/database/roles/:name` |
| `database creds <role> [--ttl]` | `POST /secrets/database/creds/:role` |
| `backup create [-o file] [--include-audit]` | Export encrypted backup |
| `backup restore -f file` | Restore encrypted backup |
| `completion [bash\|zsh\|fish]` | Generate shell completion scripts |

## Examples

```bash
# Post-install / Day-2 gate (prefer --json in automation)
knxvault-cli doctor
knxvault-cli doctor --json   # healthy:true, fail:0

knxvault-cli auth login --token dev-root-token
knxvault-cli kv put app/db password=s3cret
knxvault-cli kv get app/db                 # JSON values → [REDACTED]; stderr: use --show-secrets
knxvault-cli kv get app/db --show-secrets  # plaintext (avoid shared logs)
knxvault-cli pki issue --role root --common-name app.example.com --dns app.example.com --auto-renew
knxvault-cli sys seal
knxvault-cli sys unseal "$(cat unseal.key)"   # full key (base64); process starts sealed after Raft start
# Multi-share (threshold ≥ 2): curl with {"share":...} — docs/recipes/seal-and-unseal.md
knxvault-cli backup create -o backup.json
```

## Server binary

The server is `knxvault` (not `knxvault-cli`). Start it with `knxvault serve`. Configuration is documented in [Configuration reference](../installation/configuration.md).

When Raft is enabled, the server process requires `KNXVAULT_UNSEAL_KEY` (distinct from `KNXVAULT_MASTER_KEY`) at startup and starts **sealed** until unseal — see [Installation](../installation/install.md), [Operator security](../operations/operator-security.md), and [Seal and unseal](../recipes/seal-and-unseal.md). Lab multi-share proof: [lab-full-e2e.md](../engineering/lab-full-e2e.md).