# Secrets Manager Readiness Checklist (W37-09)

Use this checklist before promoting KNXVault to production secrets management workloads.

**Implementation status** (code complete — operator validation still required):

| Criterion | Status | Backlog | Doc |
|-----------|--------|---------|-----|
| Encryption in transit (TLS/mTLS) | ✅ Shipped | W37-01 | [tier0-production.md](tier0-production.md) |
| OIDC / short-lived credentials | ✅ Shipped | W37-02 | [tier0-production.md](tier0-production.md) |
| Machine identity (NHI) | ✅ Shipped | W37-03 | [tier0-production.md](tier0-production.md) |
| AI agent delegation | 🔶 Partial | W37-04 | `parent_identity_id` only; delegate API pending |
| Scheduled KV rotation | ✅ Shipped | W37-05 | [tier0-production.md](tier0-production.md) |
| Rotation orchestration (KV/DB/PKI + webhook) | ✅ Shipped | W37-06 | [api/reference.md](../api/reference.md) (`POST /sys/rotation/run`) |
| Exposure detection hooks | ✅ Shipped | W37-07 | [exposure-detection.md](../integration/exposure-detection.md) |
| Multi-language SDKs | 🔶 Partial | W40-03–07 | Go `pkg/client` shipped; codegen script exists |
| Raft peer mTLS | ✅ Shipped | W38-14 | [tier0-production.md](tier0-production.md) |
| CSI provider + rotation | ✅ Shipped | W39-01, W39-05 | [csi-install.md](../deploy/csi-install.md) |
| ESO + cert-manager integration | ✅ Shipped | W40-01, W40-02 | [kubernetes-native.md](../integration/kubernetes-native.md) |

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
- [ ] `knxvault_active_leases` metric reflects live leases (uses `LeaseRepository.CountActive` on leader tick)
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