# Enterprise Memorandum Traceability Matrix (W41-15)

Maps the **July 2026 Enterprise Architecture & Security Review** memorandum to implementation status, backlog priority, and prospect POC gates.

**Active delivery track:** [Tier P — Prospect POC immediate](../backlog.md#tier-p--prospect-poc-immediate-july-2026-enterprise-memorandum)

**Related:** [PoC evaluation guide](poc-evaluation-guide.md) · [ADR-0006 seal/unseal](../adr/0006-seal-unseal-strategies.md) · [Security model](../architecture/security-model.md)

---

## POC authorization gate

Prospect POC may proceed when **all** are true:

| Gate | IDs | Status |
|------|-----|--------|
| P0 documentation complete | **W41-12**, **W41-15** | ✅ Shipped |
| Memory hardening | **W41-01**, **W41-02** | ✅ Shipped |
| OpenSSL compensating control OR native PKI | **W41-13** + **W41-09** | ✅ Shipped (`KNXVAULT_PKI_BACKEND=native`) |
| Separation of duties on unseal | **W41-05** | ✅ Shipped |
| Token breach containment | **W41-06** | ✅ Shipped |
| Compensating controls deployed | StatefulSet security context | ✅ Shipped |
| Waivers signed | **LT-14** KMS, **LT-13** external DB (if applicable) | Operator sign-off |

---

## Section 2 — Core concerns

| Memorandum | Concern | Status | Code / ADR | Tier P |
|------------|---------|--------|------------|--------|
| §2.A | OpenSSL subprocess for PKI | ✅ Native path | `internal/crypto/x509native/`, `KNXVAULT_PKI_BACKEND=native` | **W41-09**, **W41-10** |
| §2.A | Process injection via shell | ✅ Shipped | `SafeExec`, **W38-11** | — |
| §2.A | Process table exhaustion | ✅ Mitigated | **W38-17** circuit breaker | — |
| §2.B | Plaintext master key bootstrap | ✅ mlock | `internal/crypto/memlock/`, `masterkey/loader.go` | **W41-01** |
| §2.B | No KMS envelope unseal | ⏳ Long-term | [ADR-0006](../adr/0006-seal-unseal-strategies.md) | **LT-14** waiver |
| §2.B | No Shamir / SoD | ✅ Shipped | `internal/crypto/shamir/`, `internal/app/seal.go` | **W41-05** |
| §2.C | Container blast radius | ✅ Shipped | `deployments/k8s/statefulset.yaml` | — |
| §2.D | No token cascade revoke | ✅ Shipped | `internal/auth/token.go` (`ParentID`, cascade) | **W41-06** |
| §2.D | No OIDC group → policy | ✅ Shipped | `internal/auth/claimmapping.go` | **W41-07** |
| §2.D | API TLS from PKI | ✅ Shipped | `POST /sys/tls/issue-listener` | **W38-15** |
| §2.D | Rigid storage / migrations | ✅ N/A | Dragonboat SM | **LT-13** non-goal |
| §2.E | HS256 K8s JWT | ✅ Shipped | **W36-02** TokenReview | — |
| §2.E | No mlock / memzero | ✅ Shipped | `memlock`, `sensitive`, `scripts/audit-sensitive.sh` | **W41-01**, **W41-02** |

---

## Section 4 — Roadmap inquiries (Q1–Q6)

| Q | Question | Answer | Evidence |
|---|----------|--------|----------|
| **Q1** | Go-native PKI? | ✅ Shipped | `internal/crypto/pki/`, `x509native/`, **W41-09** |
| **Q2** | Cloud KMS auto-unseal? | Stub + waiver | `internal/crypto/autounseal/`, **W41-14**; **LT-14** |
| **Q3** | SafeExec validation? | ✅ Shipped | **W38-11** |
| **Q4** | Shamir threshold? | ✅ Shipped | **W41-05**, [shamir-unseal](../operations/shamir-unseal.md) |
| **Q5** | K8s asymmetric validation? | ✅ Shipped | **W36-02** TokenReview |
| **Q6** | mlock and memory zeroing? | ✅ Shipped | **W41-01**, **W41-02** |

---

## Section 5 — Compensating controls

| Control | Status | Evidence |
|---------|--------|----------|
| `readOnlyRootFilesystem: true` | ✅ | `statefulset.yaml` |
| `runAsNonRoot` + drop ALL caps | ✅ | UID 65532 |
| `seccompProfile: RuntimeDefault` | ✅ | **W38-21** |
| OpenSSL-specific seccomp | ✅ | `deployments/k8s/seccomp-openssl.json`, **W41-13** |
| NetworkPolicy | ✅ | **W38-05** |
| Air-gap OpenSSL patching | ✅ | [air-gap runbook](../operations/runbooks/air-gap-image-patching.md), **W41-12** |
| Rate limit `/sys/unseal` | ✅ | `internal/api/router.go` |

---

## Waivers (prospect sign-off)

| Item | Waiver | Owner action |
|------|--------|--------------|
| **LT-14** AWS KMS auto-unseal | Accept sealed K8s Secrets + file stub | Platform team |
| **LT-15** GCP/Azure KMS | Same as LT-14 | — |
| **LT-13** Aurora/Consul storage | Accept Dragonboat-only | Architecture sign-off |

Update this matrix when waivers change or **LT-14** ships.