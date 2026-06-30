# Configuration Reference

KNXVault is configured entirely via environment variables. No config file is required; Kubernetes ConfigMaps and Secrets map directly to these variables.

## Core

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `KNXVAULT_HTTP_ADDR` | `:8200` | No | HTTP listen address |
| `KNXVAULT_LOG_LEVEL` | `info` | No | `debug`, `info`, `warn`, `error` |
| `KNXVAULT_VERSION` | `0.1.0-dev` | No | Version string in metrics and health |
| `KNXVAULT_SHUTDOWN_GRACE` | `10s` | No | Graceful shutdown timeout |

## Cryptography

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `KNXVAULT_MASTER_KEY` | — | **Yes** (prod) | Base64-encoded 32-byte master key |
| `KNXVAULT_MASTER_KEY_FILE` | — | Alt. to above | Path to base64 key file (takes priority) |
| `KNXVAULT_OPENSSL_BINARY` | `openssl` | No | OpenSSL executable path |
| `KNXVAULT_OPENSSL_TIMEOUT` | `60s` | No | Max OpenSSL command duration |

## Authentication

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `KNXVAULT_ROOT_TOKEN` | — | Bootstrap | Initial admin token |
| `KNXVAULT_JWT_SECRET` | — | Dev K8s auth | HS256 secret for local ServiceAccount JWT login (dev only; not used when TokenReview is available) |
| `KNXVAULT_K8S_AUTH_INSECURE` | `false` | Dev only | When `KNXVAULT_RAFT_ENABLED=false`, allow unvalidated K8s login (never enable in production) |
| `KNXVAULT_TOKEN_TTL` | `24h` | No | Issued client token lifetime |

## Dragonboat Raft (production storage)

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `KNXVAULT_RAFT_ENABLED` | `false` | Prod: **Yes** | Enable Dragonboat backend |
| `KNXVAULT_RAFT_NODE_ID` | auto from pod | When enabled | Unique Raft node ID (> 0) |
| `KNXVAULT_RAFT_ADDRESS` | `127.0.0.1:63001` | When enabled | Advertised Raft address |
| `KNXVAULT_RAFT_LISTEN_ADDRESS` | — | No | Bind address override |
| `KNXVAULT_RAFT_DATA_DIR` | `/var/lib/knxvault/raft` | When enabled | Pebble WAL + snapshot directory |
| `KNXVAULT_RAFT_INITIAL_MEMBERS` | — | New cluster | `id=host:port,...` peer map |
| `KNXVAULT_RAFT_JOIN` | `false` | No | Join existing cluster |
| `KNXVAULT_RAFT_ELECTION_RTT` | `10` | No | Election interval (RTT ticks) |
| `KNXVAULT_RAFT_HEARTBEAT_RTT` | `1` | No | Heartbeat interval (RTT ticks) |
| `KNXVAULT_RAFT_RTT_MILLISECOND` | `1` | No | Logical RTT milliseconds |
| `KNXVAULT_POD_NAME` | — | K8s | StatefulSet pod name for node ID derivation |

See [Dragonboat storage](../storage/dragonboat.md) for topology examples.

## Background jobs

Jobs run on the **Raft leader** when Raft is enabled.

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_JOB_LEASE_CLEANUP_INTERVAL` | `1m` | Expired lease cleanup |
| `KNXVAULT_JOB_CRL_REFRESH_INTERVAL` | `15m` | CRL pre-generation |
| `KNXVAULT_JOB_CERT_RENEW_INTERVAL` | `1h` | Auto-renewal scan |
| `KNXVAULT_RENEW_GRACE` | `72h` | Renew certs expiring within window |

## Security hardening

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_AUDIT_SIGNING_KEY` | — | HMAC key for audit export signatures |
| `KNXVAULT_RATE_LIMIT_ENABLED` | `false` | Per-token/IP rate limiting |
| `KNXVAULT_RATE_LIMIT_RPM` | `300` | Requests per minute per client |
| `KNXVAULT_REQUEST_SIGNING_KEY` | — | HMAC key for `X-KNX-Signature` header |
| `KNXVAULT_REQUEST_SIGNING_REQUIRED` | `false` | Reject unsigned requests when true |

## Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `KNXVAULT_TRACING_ENABLED` | `false` | Enable OpenTelemetry HTTP tracing |
| `KNXVAULT_OTLP_ENDPOINT` | collector default | OTLP HTTP endpoint |
| `KNXVAULT_TRACING_SAMPLE_RATIO` | `1` | Trace sampling ratio (0–1) |

## Configuration profiles

### Development (in-memory)

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_ROOT_TOKEN=dev-root-token
# KNXVAULT_RAFT_ENABLED unset → in-memory
```

### Production (3-node Raft)

Set in ConfigMap / StatefulSet:

```yaml
KNXVAULT_RAFT_ENABLED: "true"
KNXVAULT_RAFT_DATA_DIR: "/var/lib/knxvault/raft"
KNXVAULT_RAFT_INITIAL_MEMBERS: "1=knxvault-0.knxvault-raft:63001,2=knxvault-1.knxvault-raft:63001,3=knxvault-2.knxvault-raft:63001"
```

Secrets (never in ConfigMap):

```yaml
KNXVAULT_MASTER_KEY: "<base64-32-bytes>"
KNXVAULT_ROOT_TOKEN: "<bootstrap-token>"
KNXVAULT_JWT_SECRET: "<k8s-jwt-hmac>"
KNXVAULT_AUDIT_SIGNING_KEY: "<audit-hmac>"
```

## Operator security notes

| Variable | Guidance |
|----------|----------|
| `KNXVAULT_MASTER_KEY` | Never commit to git; use K8s Secret or KMS |
| `KNXVAULT_ROOT_TOKEN` | Rotate after bootstrap; replace with scoped tokens |
| `KNXVAULT_JWT_SECRET` | Dev-only HS256 K8s auth; production uses in-cluster TokenReview |
| `KNXVAULT_K8S_AUTH_INSECURE` | Never enable when Raft/production is on |
| `KNXVAULT_AUDIT_SIGNING_KEY` | Enable in production for tamper-evident audit export |

Do not store database admin passwords in database role `config` — use KV paths. See [Operator security](../operations/operator-security.md).

## Related documents

- [Operator security](../operations/operator-security.md)
- [Kubernetes deployment](../deploy/kubernetes.md)
- [Metrics](../metrics.md)
- [Tracing](../observability/tracing.md)