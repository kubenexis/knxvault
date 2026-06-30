# Day-2 Operations

Ongoing operational tasks for running KNXVault in production.

## Health monitoring

| Check | Endpoint | Expected |
|-------|----------|----------|
| Liveness | `GET /health` | `200`, status `ok` |
| Readiness | `GET /ready` | `200`, `raft_ready: true`, `leader` set |
| Metrics | `GET /metrics` | Prometheus text format |

Key metrics: `knxvault_raft_leader`, `knxvault_raft_commit_index`, `knxvault_http_request_duration_seconds`, `knxvault_rate_limited_total`.

See [Prometheus metrics](../metrics.md) and the [Grafana dashboard](../../deployments/grafana/knxvault-overview.json).

## Backup schedule

Run encrypted backups before upgrades and on a regular cadence (daily recommended).

```bash
# CLI
export KNXVAULT_ADDR=https://knxvault.internal:8200
export KNXVAULT_TOKEN=<admin-token>
./bin/knxvault-cli backup create -o "knxvault-$(date +%F).json"

# Cron wrapper
./scripts/backup.sh
```

Requirements:

- Same `KNXVAULT_MASTER_KEY` at restore time
- Admin token with `sys/backup` capability
- Store backups in encrypted object storage

Details: [Backup & restore](../deploy/backup-restore.md).

## Certificate renewal

### Automatic

Issue certificates with `"auto_renew": true`. The Raft leader job calls `RenewExpiring` every `KNXVAULT_JOB_CERT_RENEW_INTERVAL` (default 1h) for certs expiring within `KNXVAULT_RENEW_GRACE` (default 72h).

### Manual

```bash
curl -s -X POST $KNXVAULT_ADDR/pki/renew \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ca_id":"<uuid>","serial":"<serial>","ttl":"720h"}'
```

### CRL refresh

The leader pre-generates CRLs every `KNXVAULT_JOB_CRL_REFRESH_INTERVAL` (default 15m). Distribute via `GET /pki/crl/:id` or OCSP at `POST /pki/ocsp/:id`.

## Lease management

Dynamic database credentials expire automatically. The leader cleans expired leases every `KNXVAULT_JOB_LEASE_CLEANUP_INTERVAL` (default 1m).

Manual operations:

```bash
# Renew
curl -s -X POST $KNXVAULT_ADDR/secrets/database/renew/<lease_id> \
  -H "Authorization: Bearer $TOKEN"

# Revoke
curl -s -X PUT $KNXVAULT_ADDR/secrets/database/revoke/<lease_id> \
  -H "Authorization: Bearer $TOKEN"
```

## Upgrades

### Rolling upgrade (3-node Raft)

1. **Pre-upgrade backup** — `knxvault-cli backup create`
2. **Upgrade one replica at a time** — update image tag in StatefulSet, delete pod `knxvault-N`, wait for `/ready`
3. **Verify quorum** — `knxvault_raft_leader` and `knxvault_raft_commit_index` advancing
4. **Smoke test** — read/write secret, issue test cert

Raft maintains quorum with 2 of 3 nodes healthy during rolling restarts.

### Version compatibility

- Minor version upgrades preserve Raft snapshot format (`knxvault-backup` v1)
- Always read release notes for breaking API changes

## Audit review

```bash
# Export with signature
curl -s $KNXVAULT_ADDR/audit/export \
  -H "Authorization: Bearer $TOKEN" | jq

# Verify chain
curl -s -X POST $KNXVAULT_ADDR/audit/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d @audit-export.json
```

Configure `KNXVAULT_AUDIT_SIGNING_KEY` for tamper-evident exports.

## Token hygiene

1. Create scoped policies for each workload
2. Disable or rotate the bootstrap root token after initial setup
3. Use K8s SA auth for in-cluster access
4. Enable rate limiting in production: `KNXVAULT_RATE_LIMIT_ENABLED=true`

## Troubleshooting

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `/ready` 503, no leader | Raft election in progress or quorum loss | Check pod logs, PVC mounts, network between replicas |
| `forbidden` on API calls | Missing policy capability | Review `/sys/capabilities`, update policy |
| `internal_error` on PKI | OpenSSL failure | Check `KNXVAULT_OPENSSL_BINARY`, disk space in temp dirs |
| High `knxvault_rate_limited_total` | Aggressive client or attack | Tune `KNXVAULT_RATE_LIMIT_RPM`, investigate client IPs |
| Restore fails | Master key mismatch | Verify `KNXVAULT_MASTER_KEY` matches backup |

Structured logs include `request_id`, `actor`, `method`, `path`, `status`, and `latency`. Correlate with `X-Request-ID` response header.

## Runbooks

| Scenario | Document |
|----------|----------|
| CA private key compromise | [CA compromise runbook](runbooks/ca-compromise.md) |
| Raft leader loss / quorum loss | [Raft failover runbook](runbooks/raft-failover.md) |
| Scaling replicas | [Scaling runbook](runbooks/scaling.md) |

## Related documents

- [Kubernetes deployment](../deploy/kubernetes.md)
- [Configuration reference](../installation/configuration.md)
- [Tracing](../observability/tracing.md)