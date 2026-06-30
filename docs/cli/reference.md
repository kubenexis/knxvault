# CLI Reference

The `knxvault-cli` binary provides Day-2 operations against the KNXVault REST API.

## Installation

```bash
make build-cli
```

Binary: `bin/knxvault-cli`

## Configuration

| Flag / env | Default | Description |
|------------|---------|-------------|
| `--addr` / `KNXVAULT_ADDR` | `http://localhost:8200` | API base URL |
| `--token` / `KNXVAULT_TOKEN` | _(empty)_ | Bearer client token |

## Commands

| Command | Description |
|---------|-------------|
| `health` | `GET /health` |
| `status` | `GET /ready` |
| `auth login [--token]` | `POST /auth/token` |
| `kv get <path>` | Read a KV secret |
| `kv put <path> key=value...` | Write a KV secret |
| `pki issue --role --common-name [--dns] [--ttl] [--auto-renew]` | Issue a leaf certificate |
| `backup create [-o file] [--include-audit]` | Export encrypted backup |
| `backup restore -f file` | Restore encrypted backup |

## Examples

```bash
knxvault-cli auth login --token dev-root-token
knxvault-cli kv put app/db password=s3cret
knxvault-cli kv get app/db
knxvault-cli pki issue --role root --common-name app.example.com --dns app.example.com --auto-renew
knxvault-cli backup create -o backup.json
```