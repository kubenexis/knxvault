# CLI Reference

The `knxvault-cli` binary provides Day-2 operations against the KNXVault REST API.

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
| `kv get <path> [--show-secrets]` | Read a KV secret (values redacted by default) |
| `kv put <path> key=value...` | Write a KV secret |
| `pki root --name --common-name [--ttl] [--key-bits]` | Create a self-signed root CA |
| `pki issue --role --common-name [--dns] [--ttl] [--auto-renew]` | Issue a leaf certificate |
| `sys policies list` | `GET /sys/policies` |
| `sys policies get <name>` | `GET /sys/policies/:name` |
| `sys policies put <name> <json-file>` | `PUT /sys/policies/:name` |
| `sys policies delete <name>` | `DELETE /sys/policies/:name` |
| `sys roles get <name>` | `GET /sys/roles/:name` |
| `sys roles put <name> <json-file>` | `PUT /sys/roles/:name` |
| `sys rotate-master-key <base64-key>` | `POST /sys/rotate-master-key` |
| `sys rotation-run [--db-grace] [--pki-grace]` | `POST /sys/rotation/run` |
| `sys raft-add-node <id> <address>` | `POST /sys/raft/add-node` |
| `sys raft-remove-node <id>` | `POST /sys/raft/remove-node` |
| `sys issue-listener-tls` | `POST /sys/tls/issue-listener` |
| `sys seal` | `POST /sys/seal` |
| `sys unseal <base64-key>` | `POST /sys/unseal` |
| `audit export [--limit]` | `GET /audit/export` |
| `database roles put <name> <json-file>` | `PUT /secrets/database/roles/:name` |
| `database roles get <name>` | `GET /secrets/database/roles/:name` |
| `database creds <role> [--ttl]` | `POST /secrets/database/creds/:role` |
| `backup create [-o file] [--include-audit]` | Export encrypted backup |
| `backup restore -f file` | Restore encrypted backup |
| `completion [bash\|zsh\|fish]` | Generate shell completion scripts |

## Examples

```bash
knxvault-cli doctor
knxvault-cli doctor --json
knxvault-cli auth login --token dev-root-token
knxvault-cli kv put app/db password=s3cret
knxvault-cli kv get app/db
knxvault-cli kv get app/db --show-secrets
knxvault-cli pki issue --role root --common-name app.example.com --dns app.example.com --auto-renew
knxvault-cli sys seal
knxvault-cli sys unseal "$(cat unseal.key)"
knxvault-cli backup create -o backup.json
```

## Server binary

The server is `knxvault` (not `knxvault-cli`). Start it with `knxvault serve`. Configuration is documented in [Configuration reference](../installation/configuration.md).