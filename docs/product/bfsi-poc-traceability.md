<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# BFSI POC Traceability Matrix

Formal mapping of **BFSI POC must-have requirements** to KNXVault implementation evidence, backlog items, and compensating controls.

| Field | Value |
|-------|-------|
| **Product version** | v0.5.1 |
| **Matrix version** | 1.0 |
| **Last updated** | 2026-07-01 (backlog audit) |
| **Scope** | Prospect POC / regulated workload evaluation (BFSI) |
| **Authoritative spec** | Prospect BFSI POC requirements document (18 sections) |

## How to read this matrix

| Column | Meaning |
|--------|---------|
| **ID** | Stable requirement identifier (`BFSI-<section>-<n>`) |
| **Status** | **Met** · **Partial** · **Gap** · **Roadmap** (planned, not near-term) |
| **Evidence** | Code path, API, manifest, test, or doc proving implementation |
| **Backlog** | `docs/backlog.md` work item when not Met |
| **Compensating control** | Accepted workaround for POC when full feature is absent |
| **POC gate** | **Must** (POC blocker if Gap) · **Should** (expected, waiver possible) · **Could** (defer post-POC) |

### Summary by section

| § | Area | Met | Partial | Gap | POC readiness |
|---|------|-----|---------|-----|---------------|
| 1 | High Availability | 8 | 2 | 0 | **Viable** |
| 2 | Security | 6 | 4 | 2 | **Partial** — TLS/memory gaps |
| 3 | Authentication | 3 | 2 | 4 | **Narrow** — K8s/OIDC only |
| 4 | Authorization | 3 | 1 | 2 | **Partial** |
| 5 | Secret Management | 9 | 2 | 2 | **Strong** |
| 6 | Dynamic Secrets | 0 | 1 | 1 | **DB only** — no SSH |
| 7 | PKI | 8 | 2 | 1 | **Strong core** |
| 8 | Transit Encryption | 0 | 0 | 6 | **Not supported** |
| 9 | Kubernetes Integration | 7 | 1 | 0 | **Strong** — CSI, ESO, cert-manager shipped |
| 10 | APIs & SDKs | 4 | 1 | 2 | **REST/Go only** |
| 11 | Administrative CLI | 10 | 4 | 4 | **Partial** — core Day-2 CLI shipped |
| 12 | Audit | 4 | 3 | 2 | **Partial** — export formats |
| 13 | Backup & DR | 4 | 4 | 1 | **Partial** |
| 14 | Observability | 5 | 0 | 0 | **Met** |
| 15 | Performance | 0 | 0 | 7 | **Evidence required** |
| 16 | Compliance | 0 | 0 | 6 | **Roadmap** |
| 17 | Air-Gapped Deployment | 2 | 2 | 1 | **Partial** |
| 18 | Operational Readiness | 6 | 1 | 2 | **Mostly met** |

**Overall POC posture (full must-have list):** ~55% Met · ~25% Partial · ~20% Gap.  
**Recommended POC scope:** §1, §5, §7 (core), §9 (CSI), §14 + narrowed auth (K8s/OIDC) and documented waivers for §3, §6, §8, §15, §16.

---

## §1 High Availability

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-1-01 | 3+ node cluster | **Met** | Dragonboat Raft; `deployments/k8s/statefulset.yaml`; `docs/deploy/kubernetes.md` | — | — | Must |
| BFSI-1-02 | Automatic leader election | **Met** | `internal/raft/nodehost.go`; `knxvault_raft_leader` metric; `docs/storage/dragonboat.md` | — | — | Must |
| BFSI-1-03 | Automatic failover | **Met** | `test/integration/raft_test.go` `TestRaftLeaderFailover`; `test/chaos/raft-pod-kill.sh` | — | — | Must |
| BFSI-1-04 | No split-brain | **Met** | Raft quorum writes; ADR-0001, ADR-0004 | — | Document quorum sizing (3/5 nodes) in POC architecture | Must |
| BFSI-1-05 | Zero data loss during node failure | **Partial** | Committed Raft entries durable with quorum; single-node loss tolerated | W36-09 | Define RPO=0 for quorum writes, RTO from failover runbook | Must |
| BFSI-1-06 | Online node addition/removal | **Met** | `POST /sys/raft/add-node`, `POST /sys/raft/remove-node`; `internal/raft/membership.go`; `docs/operations/runbooks/scaling.md` | — | — | Should |
| BFSI-1-07 | Rolling upgrades | **Partial** | StatefulSet rolling update supported; no automated upgrade controller | LT-09 | Manual rolling restart + pre-upgrade `POST /sys/backup` per `docs/operations/day2.md` | Should |
| BFSI-1-08 | Snapshot support | **Met** | Dragonboat `SaveSnapshot` / `RecoverFromSnapshot`; `internal/raft/statemachine.go` | — | — | Must |
| BFSI-1-09 | Backup and restore | **Met** | `POST /sys/backup`, `POST /sys/restore`; `internal/backup/`; `docs/deploy/backup-restore.md` | — | — | Must |
| BFSI-1-10 | Disaster recovery procedures | **Partial** | `docs/operations/runbooks/raft-failover.md`, `docs/deploy/backup-restore.md` | W35-01 | Cross-site DR drill script + RTO/RPO sign-off for POC | Must |

---

## §2 Security

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-2-01 | AES-256 encryption at rest | **Met** | Envelope AES-256-GCM; `internal/crypto/service.go`; ADR-0003 | — | — | Must |
| BFSI-2-02 | TLS 1.3 for all communications | **Partial** | `internal/crypto/tlsconfig/tlsconfig.go` (`MinVersion: TLS 1.2`) | — | Enforce TLS 1.3 at ingress/service mesh; bump `MinVersion` to 1.3 for POC | Must |
| BFSI-2-03 | Mutual TLS (mTLS) | **Partial** | Server TLS + `KNXVAULT_TLS_*`; optional client cert on KV writes (`internal/api/middleware/mtls.go`); Raft peer mTLS (`W38-14`) | W34-01 | NetworkPolicy + ingress mTLS; require client cert on admin paths | Must |
| BFSI-2-04 | Envelope encryption | **Met** | Master-key-wrapped DEKs; `internal/crypto/keyring.go` | — | — | Must |
| BFSI-2-05 | Master key rotation | **Met** | `POST /sys/rotate-master-key`; `internal/service/masterkey.go`; CLI `sys rotate-master-key` | — | — | Must |
| BFSI-2-06 | Data encryption key rotation | **Met** | `KeyRing.ReencryptDEK`; leader job `runMasterKeyReencrypt` in `internal/app/jobs.go` | — | — | Must |
| BFSI-2-07 | Automatic key rotation | **Met** | KV rotation (`W37-05`); `POST /sys/rotation/run` orchestration (`W37-06`); PKI renewal job; DB lease renewal | — | Webhook via `KNXVAULT_ROTATION_WEBHOOK_URL` | Should |
| BFSI-2-08 | Secure secret deletion | **Partial** | `DestroyVersion`; soft delete; `internal/crypto/memzero/memzero.go` | — | Destroy + short TTL + audit; no forensic erase attestation | Should |
| BFSI-2-09 | Memory protection for sensitive data | **Gap** | `memzero` only; no `mlock` / locked buffers | — | Run on dedicated nodes; restrict ptrace; sealed Secrets for keys; accept questionnaire waiver | Must |
| BFSI-2-10 | No plaintext secret persistence | **Met** | Ciphertext + wrapped DEKs in Raft; ADR-0004/0005 | — | — | Must |

---

## §3 Authentication

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-3-01 | Kubernetes Authentication | **Met** | `POST /auth/kubernetes`; TokenReview `internal/infra/k8s/tokenreview.go`; fail-closed with Raft (`W36-01`) | — | — | Must |
| BFSI-3-02 | OIDC / OpenID Connect | **Met** | `POST /auth/oidc/:role`; `internal/auth/oidc.go` | — | — | Must |
| BFSI-3-03 | LDAP / Active Directory | **Gap** | — | — | Federate AD → OIDC IdP (Keycloak/Azure AD) and use BFSI-3-02 | Must |
| BFSI-3-04 | AppRole | **Gap** | — | — | K8s SA + role bindings + short-lived tokens (`W36-03`) | Should |
| BFSI-3-05 | Username / Password | **Gap** | — | — | OIDC with corporate IdP; no local user store | Should |
| BFSI-3-06 | Client Certificate Authentication | **Partial** | mTLS middleware verifies peer cert; no cert→role auth method | W34-02 | Map cert CN/SAN via future auth method; interim: network-layer mTLS only | Should |
| BFSI-3-07 | JWT Authentication | **Partial** | JWT via OIDC and K8s SA paths only | — | Document supported JWT issuers (`aud`/`iss` validation in `oidc.go`) | Should |
| BFSI-3-08 | Service Account Authentication | **Met** | Same as BFSI-3-01; SA bindings on roles (`W36-03`) | — | — | Must |

---

## §4 Authorization

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-4-01 | Fine-grained RBAC | **Met** | `internal/auth/rbac.go`; `internal/auth/evaluator.go`; policy conditions | — | — | Must |
| BFSI-4-02 | Policy-based access control | **Met** | `POST/GET/DELETE /sys/policies`; persisted in Raft | — | — | Must |
| BFSI-4-03 | Namespace isolation | **Partial** | `namespace` condition in evaluator; not wired in middleware | W36-14 | Per-namespace roles + SA bindings; `X-KNX-Namespace` header (pre-W32) | Should |
| BFSI-4-04 | Multi-tenancy | **Gap** | — | W32-01, W32-02 | Separate vault clusters per tenant for POC | Could |
| BFSI-4-05 | Least privilege model | **Met** | Deny-on-match RBAC; scoped tokens; SA bindings | — | — | Must |
| BFSI-4-06 | Policy inheritance | **Gap** | Flat policy lists on roles | — | Compose explicit policies per role; document in POC security pack | Could |

---

## §5 Secret Management

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-5-01 | Versioned KV Secret Engine | **Met** | `internal/engine/secrets/kvv2.go`; `POST/GET /secrets/kv/*` | — | — | Must |
| BFSI-5-02 | Secret metadata | **Met** | `GET` metadata handlers; `PathMetadata`, `VersionMetadata` in engine | — | — | Must |
| BFSI-5-03 | Labels / Tags | **Gap** | — | — | Encode tags in path convention (`app/env/key`) for POC | Could |
| BFSI-5-04 | Secret version history | **Met** | `ListVersions`; version retention (`defaultMaxVersions`) | — | — | Must |
| BFSI-5-05 | Secret rollback | **Partial** | Read prior version by version number; no atomic rollback API | — | `GET` old version + `PUT` with `cas_version` | Should |
| BFSI-5-06 | Soft delete | **Met** | `Delete` marks latest destroyed | — | — | Must |
| BFSI-5-07 | Permanent delete | **Met** | `DestroyVersion`; metadata `destroyed: true` | — | — | Must |
| BFSI-5-08 | Secret expiration | **Met** | TTL on versions; expiry enforcement in engine | — | — | Should |
| BFSI-5-09 | Secret TTL | **Met** | `PutOptions.TTL` | — | — | Should |
| BFSI-5-10 | Secret rotation | **Met** | `PUT /sys/kv-rotation`; `POST /sys/rotation/run` (`W37-06`); `runKVRotation` job | — | Webhook notifier on rotation success | Must |
| BFSI-5-11 | Secret renewal | **Partial** | Token renewal API; KV has no lease renewal | — | Re-read or re-put secret; DB leases use `POST /secrets/database/renew/:id` | Could |
| BFSI-5-12 | Secret revocation | **Partial** | Destroy version; exposure auto-revoke (`W37-07`); token revoke | — | Destroy + rotation on exposure report | Should |

---

## §6 Dynamic Secrets

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-6-01 | SSH credential generation | **Gap** | — | — | **Waive for POC** or use static SSH keys in KV with rotation (W37-05) | Must (if in scope) |
| BFSI-6-02 | Database dynamic credentials | **Met** | `internal/engine/secrets/database/`; `POST /secrets/database/creds/:role`; managed mode (`W36-18`) | W36-19 | Client mode returns SQL for operator execution | Should |

---

## §7 PKI

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-7-01 | Root CA | **Met** | `POST /pki/root`; `internal/engine/pki/engine.go` | — | — | Must |
| BFSI-7-02 | Intermediate CA | **Met** | `POST /pki/intermediate` | — | — | Must |
| BFSI-7-03 | Certificate issuance | **Met** | `POST /pki/issue`; PKI roles (`W38-03`) | — | — | Must |
| BFSI-7-04 | Certificate renewal | **Met** | `POST /pki/renew`; background renewal job | — | — | Must |
| BFSI-7-05 | Certificate revocation | **Met** | `POST /pki/revoke` | — | — | Must |
| BFSI-7-06 | CRL support | **Met** | `GET /pki/crl/:id` | — | — | Must |
| BFSI-7-07 | OCSP support | **Met** | `POST /pki/ocsp/:id` | — | — | Should |
| BFSI-7-08 | Short-lived certificates | **Met** | Role TTL validation; renewal grace window | — | — | Must |
| BFSI-7-09 | Kubernetes certificate issuance | **Met** | cert-manager Vault shim (`W40-02`); `deployments/cert-manager/clusterissuer-knxvault.yaml` | — | CronJob pattern still valid for non-cert-manager workloads | Should |
| BFSI-7-10 | ACME protocol support | **Gap** | — | — | Use cert-manager or internal PKI API; **waive ACME for POC** | Could |

---

## §8 Transit Encryption

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-8-01 | Encrypt API | **Gap** | — | — | Application-layer encryption before KV put; **waive transit engine** | Must (if in scope) |
| BFSI-8-02 | Decrypt API | **Gap** | — | — | Same as BFSI-8-01 | Must (if in scope) |
| BFSI-8-03 | Sign API | **Gap** | — | — | Use PKI `POST /pki/issue` for signing certs; not data signing service | Must (if in scope) |
| BFSI-8-04 | Verify API | **Gap** | — | — | OCSP/CRL for cert verify only | Must (if in scope) |
| BFSI-8-05 | HMAC generation | **Gap** | — | — | HMAC on exposure reports (`W37-07`) only | Must (if in scope) |
| BFSI-8-06 | Random key generation | **Gap** | — | — | `random_password` in KV rotation generator | Could |

> **POC recommendation:** Mark §8 **out of scope** unless prospect explicitly requires a transit secrets engine. No near-term backlog item; treat as Phase 5+ / custom engine.

---

## §9 Kubernetes Integration

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-9-01 | Secrets Store CSI Driver | **Met** | `cmd/knxvault-csi/`; `deployments/csi/`; `docs/deploy/csi-install.md` | W39-07 | Run `scripts/test-csi-kind.sh` in POC validation | Must |
| BFSI-9-02 | External Secrets Operator | **Met** | `knxvault-eso` webhook adapter (`W40-01`); `deployments/external-secrets/` | — | CSI `secretObjects` as alternative | Should |
| BFSI-9-03 | Kubernetes Authentication | **Met** | See BFSI-3-01 | — | — | Must |
| BFSI-9-04 | Service Account integration | **Met** | SA bindings; CSI mount auth (`W39-02`) | — | — | Must |
| BFSI-9-05 | Sidecar support | **Met** | `POST /inject/render`; `docs/deploy/secrets-injection.md` | — | Prefer CSI; sidecar as fallback | Could |
| BFSI-9-06 | Init Container support | **Met** | Same inject render API | — | Same as BFSI-9-05 | Could |
| BFSI-9-07 | Native Kubernetes API integration | **Gap** | REST only; no K8s CRD/operator | W30-01, W30-02 | GitOps via manifests + REST; no in-cluster CRD for POC | Could |

---

## §10 APIs and SDKs

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-10-01 | REST API | **Met** | `internal/api/router.go`; `docs/api/reference.md` | — | — | Must |
| BFSI-10-02 | gRPC API | **Gap** | — | LT-04 | REST + service mesh | Could |
| BFSI-10-03 | OpenAPI Specification | **Met** | `api/openapi.yaml`; `/swagger` | — | — | Must |
| BFSI-10-04 | Go SDK | **Met** | `pkg/client/` | — | — | Must |
| BFSI-10-05 | CLI | **Partial** | `cmd/knxvault-cli/` — policies, audit, database, doctor, sys ops | W36-21 | Residual: raft scaling, roles list/delete, full PKI | Must |
| BFSI-10-06 | Idempotent APIs | **Partial** | KV CAS (`cas_version`); not all endpoints idempotent | — | Document idempotent patterns in POC integration guide | Should |

---

## §11 Administrative CLI

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-11-01 | Cluster status | **Met** | `knxvault-cli health`; `GET /health`, `/ready` | — | — | Must |
| BFSI-11-02 | Cluster health | **Met** | `knxvault-cli doctor`; `pkg/doctor/` | — | — | Must |
| BFSI-11-03 | Cluster repair | **Gap** | — | — | Runbooks + manual Raft ops; no `repair` command | Could |
| BFSI-11-04 | Backup | **Met** | `knxvault-cli backup`; `POST /sys/backup` | — | — | Must |
| BFSI-11-05 | Restore | **Met** | `pkg/client.BackupRestore`; `POST /sys/restore` | — | — | Must |
| BFSI-11-06 | Snapshot management | **Gap** | API-level only | — | Use backup API; Dragonboat snapshots internal | Should |
| BFSI-11-07 | Seal | **Met** | `knxvault-cli sys seal`; `POST /sys/seal` | — | — | Must |
| BFSI-11-08 | Unseal | **Met** | `knxvault-cli sys unseal`; `POST /sys/unseal` | — | — | Must |
| BFSI-11-09 | Key rotation | **Met** | `knxvault-cli sys rotate-master-key` | — | — | Must |
| BFSI-11-10 | Certificate management | **Partial** | `knxvault-cli pki`; partial PKI surface | W36-21 | Full PKI via REST until CLI parity | Should |
| BFSI-11-11 | Policy management | **Met** | `knxvault-cli sys policies` list/get/put/delete | W36-21 | — | Should |
| BFSI-11-12 | User management | **Gap** | Token-based; no user entity | — | IdP + token create API | Should |
| BFSI-11-13 | Authentication management | **Partial** | `knxvault-cli sys roles` get/put; API for full CRUD | W36-21 | Document role binding procedures | Should |
| BFSI-11-14 | Diagnostics | **Met** | `knxvault-cli doctor` | — | — | Must |
| BFSI-11-15 | Cluster upgrade | **Gap** | — | LT-09 | Manual rolling upgrade + backup | Should |
| BFSI-11-16 | Cluster scaling | **Gap** | API ` /sys/raft/add-node` only | W36-21 | `docs/operations/runbooks/scaling.md` + API | Should |

---

## §12 Audit

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-12-01 | Every operation audited | **Met** | `internal/audit/service.go`; handlers call `Record()` | — | — | Must |
| BFSI-12-02 | Timestamp | **Met** | `audit.Entry.Timestamp` | — | — | Must |
| BFSI-12-03 | User identity | **Met** | `audit.Entry.Actor` | — | — | Must |
| BFSI-12-04 | Authentication method | **Gap** | Not first-class field | — | Encode in `details` or derive from actor prefix; enhance audit schema | Should |
| BFSI-12-05 | Source IP | **Gap** | Not in standard entry | — | Ingress/service mesh access logs correlated by `X-Request-ID` | Should |
| BFSI-12-06 | Target object | **Met** | `audit.Entry.Resource` | — | — | Must |
| BFSI-12-07 | Namespace | **Partial** | May appear in `details`; not required field | W36-14 | Require namespace in resource path or details for POC config | Should |
| BFSI-12-08 | Operation performed | **Met** | `audit.Entry.Action` | — | — | Must |
| BFSI-12-09 | Result | **Met** | `audit.Entry.Status` | — | — | Must |
| BFSI-12-10 | Correlation ID | **Partial** | `X-Request-ID` in HTTP logs/errors; not in audit entry | — | Correlate via timestamp+actor+resource; add `request_id` to audit entry | Should |
| BFSI-12-11 | Export — JSON | **Met** | `GET /audit/export` | — | — | Must |
| BFSI-12-12 | Export — Syslog | **Gap** | — | — | HTTP forwarder → syslog relay | Should |
| BFSI-12-13 | Export — Splunk | **Partial** | HTTP POST sink (`KNXVAULT_AUDIT_FORWARD_URL`) | — | Splunk HEC HTTP collector | Should |
| BFSI-12-14 | Export — Elastic | **Partial** | HTTP forward + Promtail/Loki pipeline in `docs/observability/audit-forwarding.md` | — | Elastic HTTP ingest | Should |
| BFSI-12-15 | Export — OpenTelemetry | **Gap** | OTel for HTTP traces, not audit logs | — | Forward audit JSON to OTel collector via adapter | Could |
| BFSI-12-16 | Immutable audit logs | **Met** | Hash chain + per-entry signatures (`W38-09`); `POST /audit/verify` | — | — | Must |

---

## §13 Backup & Disaster Recovery

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-13-01 | Online backup | **Met** | `POST /sys/backup` while cluster running | — | — | Must |
| BFSI-13-02 | Offline backup | **Partial** | Export from sealed snapshot files possible; not separate product mode | — | Backup from leader during maintenance window | Should |
| BFSI-13-03 | Encrypted backup | **Met** | `internal/backup/` encrypted archive | — | — | Must |
| BFSI-13-04 | Scheduled backups | **Partial** | No built-in scheduler | — | K8s CronJob calling backup API | Must |
| BFSI-13-05 | Backup verification | **Partial** | `ValidateSnapshot` (`W36-07`) on restore path | — | Restore to staging namespace in POC test plan | Must |
| BFSI-13-06 | Restore validation | **Partial** | Integration tests; manual POC checklist | — | Automated restore test in POC exit criteria | Must |
| BFSI-13-07 | Cluster recovery | **Partial** | `docs/deploy/backup-restore.md`, raft failover runbook | W35-01 | Documented drill with RTO target | Must |
| BFSI-13-08 | Node recovery | **Met** | Replace pod + Raft rejoin; PVC retention | — | — | Must |
| BFSI-13-09 | Quorum recovery | **Partial** | Runbook guidance; no automated quorum heal | — | Maintain 3+ nodes; backup before node loss | Must |

---

## §14 Observability

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-14-01 | Prometheus metrics | **Met** | `GET /metrics`; `docs/metrics.md` | — | — | Must |
| BFSI-14-02 | Health endpoints | **Met** | `GET /health`, `GET /ready` | — | — | Must |
| BFSI-14-03 | OpenTelemetry support | **Met** | `internal/infra/tracing/`; `docs/observability/tracing.md` | — | — | Should |
| BFSI-14-04 | Structured logging | **Met** | zap JSON; request_id in `internal/api/middleware/logging.go` | — | — | Must |
| BFSI-14-05 | Alerting integration | **Met** | `deployments/prometheus/knxvault-alerts.yaml` | — | — | Must |

---

## §15 Performance

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-15-01 | Concurrent clients benchmark | **Gap** | — | LT-12 | Supplier-run POC benchmark in target cluster | Must |
| BFSI-15-02 | Secret read latency | **Gap** | — | LT-12 | Same | Must |
| BFSI-15-03 | Secret write latency | **Gap** | — | LT-12 | Same | Must |
| BFSI-15-04 | Throughput | **Gap** | — | LT-12 | Same | Must |
| BFSI-15-05 | Cluster failover time | **Gap** | — | LT-12 | Measure in `TestRaftLeaderFailover` / chaos script for POC report | Must |
| BFSI-15-06 | Backup duration | **Gap** | — | LT-12 | Timed backup in POC test plan | Should |
| BFSI-15-07 | Restore duration | **Gap** | — | LT-12 | Timed restore in POC test plan | Should |

---

## §16 Compliance

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-16-01 | RBI Cyber Security Guidelines | **Roadmap** | — | W35-02 | Gap analysis + compensating controls memo for POC | Must |
| BFSI-16-02 | PCI DSS | **Roadmap** | — | W35-02 | Map vault controls to PCI secret storage requirements | Must |
| BFSI-16-03 | ISO 27001 | **Roadmap** | — | W35-02 | Control mapping document | Should |
| BFSI-16-04 | SOC 2 | **Roadmap** | — | W35-02 | Roadmap statement; audit chain as evidence | Should |
| BFSI-16-05 | NIST Cybersecurity Framework | **Roadmap** | — | W35-02 | NIST CSF mapping (Identify/Protect/Detect) | Should |
| BFSI-16-06 | DPDP Act (India) | **Roadmap** | — | W35-02 | Data residency + encryption controls doc | Must |

> Deliverable for POC: **`docs/product/bfsi-compliance-roadmap.md`** (future) — control matrix linking each framework to Met/Partial/Gap rows in this document.

---

## §17 Air-Gapped Deployment

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-17-01 | No Internet dependency | **Met** | Self-contained container; on-prem Raft | — | — | Must |
| BFSI-17-02 | Offline installation | **Partial** | `Dockerfile`, `docs/installation/install.md` | — | Air-gap image tar + private registry procedure | Must |
| BFSI-17-03 | Offline upgrades | **Partial** | Image tag promotion | — | Import new image bundle; rolling restart | Must |
| BFSI-17-04 | Offline documentation | **Partial** | Markdown in repo | LT-11 | Ship `docs/` tarball with release artifact | Should |
| BFSI-17-05 | Offline license management | **N/A** | Permissive OSS (`docs/licensing.md`) | — | SPDX allow-list bundled in image | — |

---

## §18 Operational Readiness

| ID | Requirement | Status | Evidence | Backlog | Compensating control | POC gate |
|----|-------------|--------|----------|---------|----------------------|----------|
| BFSI-18-01 | Installation Guide | **Met** | `docs/installation/install.md` | — | — | Must |
| BFSI-18-02 | Upgrade Guide | **Gap** | Day-2 mentions upgrades; no dedicated guide | — | Add `docs/operations/upgrade.md` for POC | Must |
| BFSI-18-03 | Backup & Restore Guide | **Met** | `docs/deploy/backup-restore.md` | — | — | Must |
| BFSI-18-04 | Disaster Recovery Guide | **Partial** | Runbooks + backup doc | W35-01 | Consolidate DR guide from runbooks for POC pack | Must |
| BFSI-18-05 | Operations Runbook | **Met** | `docs/operations/day2.md`; runbooks under `docs/operations/runbooks/` | — | — | Must |
| BFSI-18-06 | Troubleshooting Guide | **Gap** | Scattered in runbooks | — | `knxvault-cli doctor` + FAQ section for POC | Should |
| BFSI-18-07 | Security Hardening Guide | **Met** | `docs/architecture/security-model.md`; `docs/operations/operator-security.md`; `docs/operations/pki-security-practices.md` | — | — | Must |
| BFSI-18-08 | API Documentation | **Met** | `docs/api/reference.md`; OpenAPI; Swagger UI | — | — | Must |

---

## POC exit criteria (recommended)

Use this checklist to sign off a **narrow BFSI POC** with documented waivers.

### Must pass (no waiver)

- [ ] 3-node Raft deployed; failover test passed (`make test-integration` or chaos script)
- [ ] Backup → restore round-trip on staging cluster
- [ ] K8s TokenReview auth; `KNXVAULT_K8S_AUTH_INSECURE=false`
- [ ] TLS enabled on API (TLS 1.3 at edge or server `MinVersion` bumped)
- [ ] KV put/get + rotation policy exercised
- [ ] PKI issue + renew + revoke + CRL
- [ ] CSI mount end-to-end (`scripts/test-csi-kind.sh` or equivalent)
- [ ] Audit export + hash-chain verify
- [ ] Prometheus scrape + alert rules applied
- [ ] `knxvault-cli doctor` passes on production-like config

### Waivers (document in POC sign-off)

| Waiver | Requirement IDs | Compensating control |
|--------|-----------------|----------------------|
| Transit engine out of scope | BFSI-8-* | App-layer crypto; KV envelope at rest |
| LDAP/AppRole/userpass | BFSI-3-03–3-05 | OIDC federation + K8s SA auth |
| SSH dynamic secrets | BFSI-6-01 | KV-stored SSH keys + rotation |
| ACME | BFSI-7-10 | PKI API + cert-manager CronJob pattern |
| Memory mlock | BFSI-2-09 | Dedicated nodes, sealed Secrets, ops hardening |
| Compliance attestation | BFSI-16-* | This matrix + roadmap dates |
| Benchmarks | BFSI-15-* | POC-specific benchmark report (LT-12) |

### Implementation priority to close POC gaps

| Priority | Backlog IDs | Closes |
|----------|-------------|--------|
| P0 | ~~W40-01~~, ~~W40-02~~, ~~W37-06~~, W36-21 `[Partial]` | **Done** except residual CLI parity |
| P1 | W36-14, W36-09, W36-15 `[Partial]`, audit schema enhancement | Namespace RBAC, leader status, metrics docs, audit fields |
| P2 | W35-02, LT-12, `docs/operations/upgrade.md` | Compliance roadmap, benchmarks, upgrade guide |
| P3 | W32-*, LT-04, transit engine (new) | Multi-tenancy, gRPC, §8 |

---

## Related documents

- [Secrets manager checklist](secrets-manager-checklist.md)
- [LLD alignment matrix](lld-alignment.md)
- [Backlog](../backlog.md)
- [Kubernetes-native integrations](../integration/kubernetes-native.md)
- [Security model](../architecture/security-model.md)