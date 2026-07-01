# Secrets Manager Readiness Checklist (W37-09)

Use this checklist before promoting KNXVault to production secrets management workloads.

**Implementation status** (code complete — operator validation still required):

| Criterion | Status | Backlog | Doc |
|-----------|--------|---------|-----|
| Encryption in transit (TLS/mTLS) | ✅ Shipped | W37-01 | [tier0-production.md](tier0-production.md) |
| OIDC / short-lived credentials | ✅ Shipped | W37-02 | [tier0-production.md](tier0-production.md) |
| Machine identity (NHI) | ✅ Shipped | W37-03 | [tier0-production.md](tier0-production.md) |
| Scheduled KV rotation | ✅ Shipped | W37-05 | [tier0-production.md](tier0-production.md) |
| Exposure detection hooks | ✅ Shipped | W37-07 | [exposure-detection.md](../integration/exposure-detection.md) |
| Raft peer mTLS | ✅ Shipped | W38-14 | [tier0-production.md](tier0-production.md) |
| CSI secret rotation | ✅ Shipped | W39-05 | [secrets-injection.md](../deploy/secrets-injection.md) |

### Enterprise security (Tier I — planned)

| Criterion | Status | Backlog | Doc |
|-----------|--------|---------|-----|
| Memory lock (`mlock`) for root keys | ⏳ Planned | W41-01 | [poc-evaluation-guide.md](poc-evaluation-guide.md) |
| Cloud KMS auto-unseal (AWS/GCP/Azure) | ⏳ Long-term | LT-14, LT-15 | [backlog.md](../backlog.md) |
| Shamir threshold unseal (unseal key only) | ⏳ Planned | W41-05 | [ADR-0006](../adr/0006-seal-unseal-strategies.md) |
| Dual-mode unseal (KMS + Shamir break-glass) | ⏳ Planned | W41-14, LT-14 | [ADR-0006](../adr/0006-seal-unseal-strategies.md) |
| HSM-wrapped master key | ⏳ Planned | W31-03 | [ADR-0006](../adr/0006-seal-unseal-strategies.md) |
| Hierarchical token cascade revoke | ⏳ Planned | W41-06 | [backlog.md](../backlog.md) |
| OIDC group/claim → policy mapping | ⏳ Planned | W41-07 | [backlog.md](../backlog.md) |
| Go-native PKI (no OpenSSL subprocess) | ⏳ Planned | W41-08–W41-10 | [ADR-0002](../adr/0002-openssl-cli-crypto-backend.md) |
| Air-gap OpenSSL patching runbook | ⏳ Planned | W41-12 | [poc-evaluation-guide.md](poc-evaluation-guide.md) |

## Core capabilities

- [ ] Master key configured (`KNXVAULT_MASTER_KEY` or file) and rotation procedure documented
- [ ] Raft enabled (`KNXVAULT_RAFT_ENABLED=true`) with 3+ nodes and persistent volumes
- [ ] Backup/restore tested (`POST /sys/backup`, `POST /sys/restore`) including PKI roles and audit entries
- [ ] RBAC policies and roles loaded; root token rotated or disabled after bootstrap
- [ ] Audit log forwarding or export signing configured for compliance
- [ ] TLS enabled (`KNXVAULT_TLS_CERT` / `KNXVAULT_TLS_KEY`) or ingress TLS documented

## PKI

- [ ] Root and intermediate CAs created with documented TTL and rotation
- [ ] PKI roles persisted and included in backups (`pki_roles` in snapshot)
- [ ] CRL refresh and certificate renewal jobs running on leader
- [ ] OCSP endpoint reachable from clients that require stapling

## Dynamic secrets

- [ ] Database roles use client execution mode with documented SQL templates
- [ ] Lease TTLs aligned with application session lifetime
- [ ] `knxvault_active_leases` metric reflects live leases (not cleanup batch size)
- [ ] Expired lease cleanup verified on leader failover

## Kubernetes integration

- [ ] StatefulSet deployment (not legacy `Deployment` manifest)
- [ ] TokenReview authentication enabled; `KNXVAULT_K8S_AUTH_INSECURE=false`
- [ ] NetworkPolicy restricts Raft and HTTP surfaces
- [ ] CSI provider or inject webhook tested for target namespaces
- [ ] CSI rotation polling enabled on SecretProviderClass

## Operations

- [ ] `/health`, `/ready`, and `/metrics` monitored
- [ ] Raft leader and term metrics alerted
- [ ] Runbooks: [Raft failover](../operations/runbooks/raft-failover.md), [CA compromise](../operations/runbooks/ca-compromise.md)
- [ ] Integration test suite passes: `make test-integration`
- [ ] Exposure report signing key configured if using scanner integration