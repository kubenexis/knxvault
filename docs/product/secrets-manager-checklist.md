# Secrets Manager Readiness Checklist (W37-09)

Use this checklist before promoting KNXVault to production secrets management workloads.

## Core capabilities

- [ ] Master key configured (`KNXVAULT_MASTER_KEY` or file) and rotation procedure documented
- [ ] Raft enabled (`KNXVAULT_RAFT_ENABLED=true`) with 3+ nodes and persistent volumes
- [ ] Backup/restore tested (`POST /sys/backup`, `POST /sys/restore`) including PKI roles and audit entries
- [ ] RBAC policies and roles loaded; root token rotated or disabled after bootstrap
- [ ] Audit log forwarding or export signing configured for compliance

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

## Operations

- [ ] `/health`, `/ready`, and `/metrics` monitored
- [ ] Raft leader and term metrics alerted
- [ ] Runbooks: [Raft failover](../operations/runbooks/raft-failover.md), [CA compromise](../operations/runbooks/ca-compromise.md)
- [ ] Integration test suite passes: `make test-integration`