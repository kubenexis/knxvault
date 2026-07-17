# Day-2 Operations

Ongoing operational tasks for running KNXVault in production.

> **New operators:** start with the [operator runbook](operator-runbook.md) — **Day-0** (install through first cert/secret) and **Day-2** (this page’s ongoing tasks).  
> Security checklist: [Operator security guidance](operator-security.md) — credential placement, audit discipline, and cleartext metadata expectations.

## Health monitoring

| Check | Endpoint / command | Expected |
|-------|--------------------|----------|
| Liveness | `GET /health` | `200`, `status: healthy` |
| Readiness | `GET /ready` | `200`, `status: ready`, `sealed: false`; with Raft: `raft_ready: true` and exactly one leader cluster-wide |
| Operator gate | `knxvault-cli doctor --json` | `healthy: true`, `fail: 0` (HTTP TLS warn is lab-only) |
| Metrics | `GET /metrics` | Prometheus text format |

| `/ready` field | Meaning |
|----------------|---------|
| `sealed` | Must be `false` for writes |
| `raft_enabled` / `raft_ready` | Raft configured and cluster usable |
| `leader` | This process runs background jobs |

Key metrics: `knxvault_raft_leader`, `knxvault_raft_commit_index`, `knxvault_http_request_duration_seconds`, `knxvault_rate_limited_total`.

See [Prometheus metrics](../metrics.md) and the [Grafana dashboard](../../deployments/grafana/knxvault-overview.json). Post-install sequence: [Installation — verify](../installation/install.md#post-install-verify).

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

## PKI and TLS

Full PKI operations (CA hierarchy, issuance, trust bundles, Kubernetes integration):

| Guide | Topics |
|-------|--------|
| [PKI administration](pki-administration.md) | Root/intermediate/leaf recipes, import/export, renewal, revocation, CSR sign |
| [Replace cert-manager](pki-replace-cert-manager.md) | **Preferred** — knxvault-operator CRDs, no cert-manager |
| [PKI Kubernetes integration](pki-kubernetes.md) | Ingress TLS, CronJob, operator, optional Vault profile |
| [cert-manager recipe](../recipes/cert-manager-integration.md) | Optional legacy Vault issuer (`/v1/*`) |
| [PKI security best practices](pki-security-practices.md) | Trust hierarchy, key handling, production checklist |

### Certificate renewal (summary)

| Path | How renewal works |
|------|-------------------|
| **API / auto_renew** | Issue with `"auto_renew": true`. Raft leader job `RenewExpiring` every `KNXVAULT_JOB_CERT_RENEW_INTERVAL` (default 1h) within `KNXVAULT_RENEW_GRACE` (default 72h). |
| **Operator CRD** | `KNXVaultCertificate` renews when within `renewBefore`; prefers `POST /pki/renew` when `status.caId` + serial are set |
| **Manual** | `POST /pki/renew` with `ca_id`, `serial`, and `ttl` |

CRL: `GET /pki/crl/:id`. OCSP: `POST /pki/ocsp/:id`. CSR sign (operator / Vault profile): `POST /pki/sign` or `POST /v1/<mount>/sign/<role>`.

### Operator health (lab / production)

```bash
# Full lab suite: Shamir multi-share unseal + core + vaultcompat + operator + multi-issuer
make lab-full-e2e LAB_HOST=192.168.137.131
# or: bash scripts/lab-full-e2e.sh
```

Last full run: **53/53 PASS** — [Lab full E2E](../engineering/lab-full-e2e.md).  
Test map: [E2E and lab tests](../engineering/e2e-and-lab-tests.md).  
After Raft restart, process starts **sealed**; unseal (key or shares) before operator vault-mode CA create.

## Lease management

Dynamic **database** and **SSH** credentials expire automatically. The Raft leader:

- Cleans expired leases every `KNXVAULT_JOB_LEASE_CLEANUP_INTERVAL` (default 1m)
- Renews expiring database and SSH leases on `KNXVAULT_JOB_CERT_RENEW_INTERVAL` (default 1h) within a 24h grace window
- Supports orchestrated renewal via `POST /sys/rotation/run` with optional `db_grace`, `ssh_grace`, and `pki_grace`

Full runbook: [Lease management](lease-management.md). Engine guides: [Database credentials](../deploy/database-credentials.md), [Dynamic SSH credentials](../recipes/dynamic-ssh-credentials.md).

Manual operations:

```bash
# Database renew / revoke
curl -s -X POST $KNXVAULT_ADDR/secrets/database/renew/<lease_id> \
  -H "Authorization: Bearer $TOKEN"
curl -s -X PUT $KNXVAULT_ADDR/secrets/database/revoke/<lease_id> \
  -H "Authorization: Bearer $TOKEN"

# SSH renew / revoke
curl -s -X POST $KNXVAULT_ADDR/secrets/ssh/renew/<lease_id> \
  -H "Authorization: Bearer $TOKEN"
curl -s -X PUT $KNXVAULT_ADDR/secrets/ssh/revoke/<lease_id> \
  -H "Authorization: Bearer $TOKEN"

# Bulk revoke by role (incident)
curl -s -X PUT $KNXVAULT_ADDR/sys/leases/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"engine":"database","role":"compromised-role"}'
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
| `internal_error` on PKI | Native PKI issuance failure | Check server logs and CA configuration |
| High `knxvault_rate_limited_total` | Aggressive client or attack | Tune `KNXVAULT_RATE_LIMIT_RPM`, investigate client IPs |
| Restore fails | Master key mismatch | Verify `KNXVAULT_MASTER_KEY` matches backup |

Structured logs include `request_id`, `actor`, `method`, `path`, `status`, and `latency`. Correlate with `X-Request-ID` response header.

## Runbooks

| Scenario | Document |
|----------|----------|
| CA private key compromise | [CA compromise runbook](runbooks/ca-compromise.md) · [PKI security practices](pki-security-practices.md) |
| Raft leader loss / quorum loss | [Raft failover runbook](runbooks/raft-failover.md) |
| Scaling replicas | [Scaling runbook](runbooks/scaling.md) |

## Related documents

- [Kubernetes deployment](../deploy/kubernetes.md)
- [Configuration reference](../installation/configuration.md)
- [Tracing](../observability/tracing.md)