# Enterprise Memorandum Traceability Matrix (W41-15)

Maps the **July 2026 Enterprise Architecture & Security Review** memorandum to implementation status, backlog priority, and prospect POC gates.

**Active delivery track:** [Tier P — Prospect POC immediate](../backlog.md#tier-p--prospect-poc-immediate-july-2026-enterprise-memorandum)

**Related:** [PoC evaluation guide](poc-evaluation-guide.md) · [ADR-0006 seal/unseal](../adr/0006-seal-unseal-strategies.md) · [Security model](../architecture/security-model.md)

---

## POC authorization gate

Prospect POC may proceed when **all** are true:

| Gate | IDs |
|------|-----|
| P0 documentation complete | **W41-12**, **W41-15** (this doc) |
| Memory hardening | **W41-01**, **W41-02** |
| OpenSSL compensating control OR native PKI | **W41-13** + **W41-09** (native PKI required for memorandum sign-off) |
| Separation of duties on unseal | **W41-05** |
| Token breach containment | **W41-06** |
| Compensating controls deployed | StatefulSet security context (shipped) |
| Waivers signed | **LT-14** KMS, **LT-13** external DB (if applicable) |

---

## Section 2 — Core concerns

| Memorandum | Concern | Status | Code / ADR | Tier P | Waiver / near-term |
|------------|---------|--------|------------|--------|-------------------|
| §2.A | OpenSSL subprocess for PKI | ⏳ **P3** | `internal/crypto/openssl/`, [ADR-0002](../adr/0002-openssl-cli-crypto-backend.md) | **W31-01** → **W41-09** | **W41-13** seccomp until native ships |
| §2.A | Process injection via shell | ✅ Shipped | `SafeExec` argv slices, **W38-11** fuzz | — | — |
| §2.A | Process table exhaustion | ✅ Mitigated | Circuit breaker **W38-17**, timeouts | — | **W41-09** removes fork-per-issue |
| §2.B | Plaintext master key bootstrap | ⏳ Compensating | [ADR-0003](../adr/0003-envelope-encryption.md), [ADR-0006](../adr/0006-seal-unseal-strategies.md) | **W41-01** mlock | Sealed Secrets; **LT-14** long-term |
| §2.B | No KMS envelope unseal | ⏳ Long-term | — | — | **LT-14**, **LT-15**; sealed Secret waiver |
| §2.B | No Shamir / SoD | ⏳ **P2** | `internal/app/seal.go` | **W41-05** | — |
| §2.C | Container blast radius | ✅ Shipped | `deployments/k8s/statefulset.yaml` | — | — |
| §2.D | No token cascade revoke | ⏳ **P3** | `internal/auth/token.go` | **W41-06** | — |
| §2.D | No OIDC group → policy | ⏳ **P2** | `internal/auth/oidc.go` | **W41-07** | — |
| §2.D | Rigid storage / migrations | ✅ N/A | Dragonboat SM, empty `migrations/` | — | **LT-13** non-goal |
| §2.E | HS256 K8s JWT | ✅ Shipped | **W36-02** TokenReview | — | HS256 blocked with Raft |
| §2.E | No mlock / memzero | ⏳ **P1** | `memzero` partial **W38-10** | **W41-01**, **W41-02** | — |

---

## Section 4 — Roadmap inquiries (Q1–Q6)

| Q | Question | Answer | Tier P / backlog |
|---|----------|--------|------------------|
| **Q1** | Go-native PKI (remove OpenSSL fork)? | **In progress — prospect gate** | **P2** **W31-01**, **W41-08** · **P3** **W41-09**, **W41-10** |
| **Q2** | Cloud KMS auto-unseal? | **Not near-term**; sealed Secrets for POC | **LT-14**, **LT-15**; **W41-14** post-prospect |
| **Q3** | SafeExec validation framework? | **Shipped** | **W38-11**, `wrapper.go` |
| **Q4** | Shamir threshold splitting? | **P2 delivery** — unseal key only ([ADR-0006](../adr/0006-seal-unseal-strategies.md)) | **W41-05** |
| **Q5** | K8s asymmetric / JWKS validation? | **Shipped** (TokenReview); optional JWKS mode later | **W36-02**; **W41-11** optional |
| **Q6** | mlock and memory zeroing? | **P1 delivery** | **W41-01**, **W41-02** |

---

## Section 5 — Compensating controls

| Control | Required for POC | Status | Evidence |
|---------|------------------|--------|----------|
| `readOnlyRootFilesystem: true` | Yes | ✅ Shipped | `statefulset.yaml` |
| `runAsNonRoot` + drop ALL caps | Yes | ✅ Shipped | UID 65532 |
| `seccompProfile: RuntimeDefault` | Yes | ✅ Shipped | **W38-21** |
| OpenSSL-specific seccomp | Yes (until native PKI) | ⏳ **P1** | **W41-13** |
| NetworkPolicy | Yes | ✅ Shipped | **W38-05** |
| Air-gap OpenSSL patching procedure | Yes (air-gap prospects) | ⏳ **P0** | **W41-12** |
| Rate limit `/sys/unseal` | Yes | ✅ Shipped | `internal/api/router.go` |

---

## Waivers (prospect sign-off)

| Item | Waiver | Owner action |
|------|--------|--------------|
| **LT-14** AWS KMS auto-unseal | Accept sealed K8s Secrets + rotation runbook | Platform team injects master key via Sealed Secrets / ESO |
| **LT-15** GCP/Azure KMS | Same as LT-14 | — |
| **LT-13** Aurora/Consul storage | Accept Dragonboat-only ([ADR-0001](../adr/0001-dragonboat-storage-backend.md)) | Architecture sign-off |
| OpenSSL PKI during Tier P weeks 1–7 | Accept **W41-13** seccomp + SafeExec controls | Security sign-off until **W41-09** lands |

---

## Tier P timeline (summary)

| Week | Deliverables |
|------|--------------|
| 1 | **W41-12**, **W41-15** |
| 2–4 | **W41-01**, **W41-02**, **W41-13** |
| 5–7 | **W41-05**, **W31-01**, **W41-08**, **W38-15**, **W41-07** |
| 8–12 | **W41-09**, **W41-06**, **W41-10** |

Update this matrix when Tier P items ship or waivers change.