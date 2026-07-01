# KNXVault Proof of Concept (PoC) Evaluation Guide

This guide helps security architects, platform engineers, and procurement teams evaluate KNXVault **v0.4.5+** in a controlled environment before production commitment.

**Audience:** Enterprise customers, regulated-industry PoCs, and internal Kubenexis field teams.

**Related documents:**

| Document | Purpose |
|----------|---------|
| [Secrets manager checklist](secrets-manager-checklist.md) | Production readiness criteria |
| [Security model](../architecture/security-model.md) | Threat model and crypto controls |
| [Operator security](../operations/operator-security.md) | Bootstrap and credential hygiene |
| [Backlog — Tier I](../backlog.md#tier-i--enterprise-security--compliance-v10v12) | Roadmap for enterprise gaps |
| [Kubernetes deployment](../deploy/kubernetes.md) | 3-node Raft install |

---

## 1. What KNXVault is (and is not)

KNXVault is a **Kubernetes-native secrets manager and internal PKI** platform:

- Encrypted KV secrets (envelope AES-256-GCM, encrypt-before-Raft replication)
- Dynamic database credentials with lease lifecycle
- PKI (root/intermediate CA, leaf issuance, CRL, OCSP)
- RBAC, hash-chained audit logs, Dragonboat Raft HA
- CSI Driver, mutating webhook, and sidecar injection patterns

**It is not** a drop-in replacement for HashiCorp Vault / OpenBao in every enterprise dimension today. Gaps are tracked explicitly in [Tier I backlog items](../backlog.md#tier-i--enterprise-security--compliance-v10v12) (W41-*).

---

## 2. PoC suitability matrix

| Workload | PoC ready? | Notes |
|----------|------------|-------|
| K8s ServiceAccount-authenticated secret consumption (CSI / inject) | **Yes** | TokenReview production path |
| Internal TLS / mTLS certificate issuance | **Yes** | OpenSSL subprocess for X.509; sandboxed wrapper |
| Encrypted application secrets (KVv2) | **Yes** | Envelope crypto is Go-native |
| Dynamic database credentials | **Yes** | Client or managed execution mode |
| Multi-tenant regulated production (SOC2/PCI/HIPAA) | **No** | Requires compensating controls + roadmap items |
| Air-gap without image rebuild discipline | **Partial** | See [air-gap patching runbook](../backlog.md) (**W41-12**) |
| Cloud KMS auto-unseal (no plaintext master key in Pod spec) | **No** | **LT-14**, **LT-15** — use sealed Secrets for PoC |
| Shamir threshold unseal (unseal key only) | **No** | **W41-05** — single unseal key today |
| Dual-mode unseal (KMS + Shamir break-glass) | **No** | **W41-14** + **LT-14** |
| Hierarchical token cascade revoke | **No** | **W41-06** — per-token revoke only |
| OIDC AD group → policy mapping | **No** | **W41-07** — static role policies only |
| OpenSSL-free / distroless PKI | **No** | **W41-09** — native `crypto/x509` planned v1.2 |

**Recommendation:** Proceed with PoC when scope is **in-cluster K8s secrets + PKI pilot** under infrastructure compensating controls. Defer regulated multi-tenant production until v1.0 GA criteria (below) are met or explicitly waived.

---

## 3. Architecture clarifications (common review findings)

### 3.1 Cryptography split

| Operation | Engine | Subprocess? |
|-----------|--------|-------------|
| Secret encryption at rest | Go `crypto/aes` (AES-256-GCM envelope) | No |
| Raft replication | Dragonboat | No |
| X.509 (CA, leaf, CRL, OCSP) | OpenSSL 3.x CLI via `SafeExec` | Yes |

Envelope encryption does **not** fork OpenSSL. Only PKI mutating operations do. See [ADR-0002](../adr/0002-openssl-cli-crypto-backend.md).

### 3.2 Kubernetes authentication

Production clusters use **`authentication.k8s.io/v1` TokenReview** — not HS256 `KNXVAULT_JWT_SECRET`. Dev-only HS256 and `KNXVAULT_K8S_AUTH_INSECURE` are **rejected when Raft is enabled**.

OIDC login uses **JWKS + RS256/RS384/RS512** validation.

### 3.3 Storage model

Production state lives in an **embedded Dragonboat Raft cluster** (Pebble WAL + snapshots). External databases (Aurora, Consul) are **not supported** and documented as a non-goal ([LT-13](../backlog.md), [ADR-0001](../adr/0001-dragonboat-storage-backend.md)). Schema evolves via Raft state machine commands — there is no SQL `/migrations` path.

### 3.4 Seal / unseal (two-layer model)

KNXVault follows Vault-style separation documented in [ADR-0006](../adr/0006-seal-unseal-strategies.md):

| Layer | Key | Purpose | PoC custody |
|-------|-----|---------|-------------|
| **Data at rest** | Master key (`KNXVAULT_MASTER_KEY`) | Decrypts envelope-wrapped secrets and CA keys in Raft | Sealed K8s Secret or ESO — **not** Shamir-split |
| **Operations** | Unseal key (`KNXVAULT_UNSEAL_KEY`) | Gates sealed → unsealed (mutations allowed) | Separate sealed Secret; future Shamir (**W41-05**) |

- Master and unseal keys **must differ** when Raft is enabled.
- Seal blocks mutating operations; reads and `POST /sys/unseal` remain available.
- **Master key loss:** backup restore + `POST /sys/rotate-master-key` — not Shamir recovery.
- **Production target:** KMS auto-unseal for restarts (**LT-14**) + Shamir break-glass (**W41-14**); master key via KMS wrap or **W31-03** HSM.

---

## 4. Required compensating controls for PoC

Your security team should enforce these boundaries during evaluation:

| Control | KNXVault default | PoC requirement |
|---------|------------------|-----------------|
| `readOnlyRootFilesystem` | ✅ StatefulSet manifest | Keep enabled |
| `runAsNonRoot` + drop ALL caps | ✅ UID 65532 | Keep enabled |
| `seccompProfile: RuntimeDefault` | ✅ Shipped | Keep enabled |
| NetworkPolicy on Raft + HTTP | Manifests provided | Apply and restrict `/metrics` |
| TLS at ingress or server TLS | Operator config | Enable **W37-01** server TLS or ingress |
| Master key in sealed Secret / ESO | Operator responsibility | **Never** plain ConfigMap |
| Restrict `/sys/unseal` | Public by design | NetworkPolicy allowlist ops CIDR only |
| Rate limiting | Configurable | Enable `KNXVAULT_RATE_LIMIT_ENABLED` |
| Audit signing | Optional | Set `KNXVAULT_AUDIT_SIGNING_KEY` |
| Root token rotation | Operator responsibility | Replace with scoped roles post-bootstrap |

---

## 5. PoC deployment path (recommended)

### Phase A — Lab bootstrap (Day 1)

1. Deploy 3-node Raft StatefulSet per [kubernetes.md](../deploy/kubernetes.md)
2. Inject secrets via sealed-secrets or manual K8s Secret (not git):
   - `KNXVAULT_MASTER_KEY` (32-byte, base64)
   - `KNXVAULT_UNSEAL_KEY` (distinct from master key)
   - `KNXVAULT_ROOT_TOKEN` (bootstrap only)
3. Run health checks:

```bash
knxvault-cli doctor --addr https://knxvault.knxvault.svc:8200
```

4. `POST /sys/init` — create root CA (one-time)
5. Define RBAC policies and K8s SA-bound roles; revoke or scope root token

### Phase B — Workload integration (Days 2–5)

1. Install Secrets Store CSI Driver + KNXVault provider ([csi-install.md](../deploy/csi-install.md))
2. Create `SecretProviderClass` + test pod mount
3. Configure `POST /auth/kubernetes` login from a workload SA
4. Issue a test leaf cert via PKI role; verify renewal job on leader

### Phase C — Resilience drills (Days 5–10)

| Drill | Pass criteria |
|-------|---------------|
| Raft leader failover | Writes resume &lt;30s; `knxvault-cli doctor` HA checks green |
| `POST /sys/backup` + restore to fresh node | KV + PKI roles + audit chain intact |
| Seal → unseal | Mutations blocked when sealed; restored after unseal |
| Wrong SA login | TokenReview + binding → `403` |
| OpenSSL circuit breaker | Simulated PKI failure → 503, breaker metric fires |

### Phase D — Security validation (Days 10–14)

- Confirm `KNXVAULT_K8S_AUTH_INSECURE` and `KNXVAULT_JWT_SECRET` absent in production manifest
- Verify config file mode `0600` if using file-based config
- Export audit chain; verify `POST /audit/verify`
- Review Prometheus alerts ([knxvault-alerts.yaml](../../deployments/prometheus/knxvault-alerts.yaml))

---

## 6. PoC success criteria (acceptance tests)

Use these as formal PoC exit criteria. All should pass unless explicitly waived in writing.

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | 3-node Raft quorum healthy | `/ready` + `knxvault_raft_leader` metric |
| 2 | KV put/get via CSI mount | Pod reads mounted secret file |
| 3 | K8s SA auth with role binding | Correct SA → token; wrong SA → `403` |
| 4 | PKI leaf issuance + renewal | Cert issued; auto-renew before expiry |
| 5 | Backup/restore round-trip | `knxvault-cli sys backup` + restore on cold node |
| 6 | Seal/unseal operational drill | Documented runbook executed successfully |
| 7 | Audit chain integrity | `POST /audit/verify` passes |
| 8 | `knxvault-cli doctor` all green | Exit code 0 |
| 9 | No plaintext master key in ConfigMap | Manifest review |
| 10 | NetworkPolicy blocks unauthorized Raft peer | Negative connectivity test |

---

## 7. Known gaps and roadmap

Capabilities requested in enterprise security reviews map to backlog items:

| Capability | Status (v0.4.5) | Backlog | Target release |
|------------|-----------------|---------|----------------|
| `mlock` for master/unseal keys | Gap | **W41-01** | v1.0 GA |
| Universal sensitive-buffer zeroing | Partial | **W41-02** | v1.0 GA |
| AWS KMS auto-unseal | Gap | **LT-14** | Long-term |
| GCP/Azure KMS auto-unseal | Gap | **LT-15** | Long-term |
| Shamir k-of-n unseal (unseal key) | Gap | **W41-05** | v1.1 |
| Dual-mode KMS + Shamir break-glass | Gap | **W41-14**, **LT-14** | Long-term KMS; v1.1 design |
| HSM-wrapped master key | Gap | **W31-03** | Phase 5 |
| Hierarchical token cascade revoke | Gap | **W41-06** | v1.1 |
| OIDC group → policy mapping | Gap | **W41-07** | v1.1 |
| Go-native PKI (no OpenSSL fork) | Gap | **W41-08–W41-10** | v1.2 |
| K8s JWKS direct validation | Gap | **W41-11** | v1.1 (optional) |
| Air-gap OpenSSL patching runbook | Gap | **W41-12** | v1.1 (docs) |
| OpenSSL child seccomp profile | Gap | **W41-13** | v1.2 |
| Helm chart | Gap | **LT-03** | Post-v1.0 |

**v1.0 GA estimate:** Q3–Q4 2026 (remaining W36 tiers + W41-01/02 + W38-15 TLS bootstrap).

---

## 8. PoC scope templates

### Minimal PoC (2 weeks)

- Single namespace, 3-node Raft, CSI mount, one KV secret, one PKI role, K8s SA auth

### Standard PoC (4 weeks)

- Minimal + backup/restore + seal drill + failover + audit export + dynamic DB creds (SQLite or test MySQL)

### Enterprise security PoC (6 weeks)

- Standard + compensating-control audit + threat-model walkthrough + roadmap review session + optional Falco rules (**LT-08**)

---

## 9. OpenSSL in air-gap environments

For isolated environments:

1. Build image from pinned `debian:bookworm-slim` digest ([Dockerfile](../../Dockerfile))
2. Generate SBOM: `make sbom`
3. Scan: `make scan` (Trivy)
4. Push to air-gap registry; deploy via rolling StatefulSet update
5. Pre-upgrade backup: `POST /sys/backup`

Full procedure: **W41-12** runbook (`docs/operations/runbooks/air-gap-image-patching.md` — planned). Until shipped, follow the steps above and track OpenSSL CVEs via Debian security advisories.

---

## 10. Getting help

| Channel | Use for |
|---------|---------|
| GitHub Issues | Bugs and feature requests |
| `knxvault-cli doctor --json` | Attach output to support tickets |
| [Backlog](../backlog.md) | Roadmap transparency |
| [API reference](../api/reference.md) | Integration details |

For regulated PoCs, request a **joint architecture session** covering TokenReview auth, `SafeExec` sandbox, seal/unseal model, and Tier I roadmap commitments.

---

## 11. Decision framework

| Your requirement | PoC now? | Production now? | Wait for |
|------------------|----------|-----------------|----------|
| K8s-native secrets + PKI | ✅ | With compensating controls | v1.0 GA for hardening |
| No OpenSSL subprocess | ❌ | ❌ | W41-09 (v1.2) |
| KMS auto-unseal (master + routine unseal) | ❌ | ❌ | LT-14, LT-15 (long-term) |
| Shamir unseal (operational quorum) | ❌ | ❌ | W41-05 (v1.1) |
| KMS + Shamir dual-mode | ❌ | ❌ | W41-14 + LT-14 |
| HSM-wrapped master key | ❌ | ❌ | W31-03 (Phase 5) |
| AD group OIDC mapping | ❌ | ❌ | W41-07 (v1.1) |
| External DB storage (Aurora) | ❌ | ❌ | Not planned (LT-13) |

**Bottom line:** KNXVault is appropriate for a **scoped, compensating-controls PoC** evaluating Kubernetes-native secrets and internal PKI. Use **sealed Secrets for the master key** and a **separate unseal key** today; plan for **KMS + Shamir break-glass** ([ADR-0006](../adr/0006-seal-unseal-strategies.md)) in production. Not yet a full enterprise secrets platform replacement without accepting documented gaps and roadmap timelines.