# ADR-0006: Seal / Unseal and Master Key Custody Strategies

**Status:** Accepted  
**Date:** 2026-07

## Context

KNXVault separates **data-at-rest encryption** (master key + envelope crypto) from **operational seal state** (unseal key). Enterprise reviewers asked whether Shamir secret sharing, cloud KMS auto-unseal, or HSM should protect the root of trust, and whether these mechanisms overlap.

Industry practice (HashiCorp Vault, OpenBao) distinguishes:

| Key material | Purpose | Typical protection |
|--------------|---------|-------------------|
| **Master key** | Decrypts envelope-wrapped DEKs (secrets, CA private keys in storage) | KMS wrap, HSM, or sealed Secret — **long-lived, rarely rotated** |
| **Unseal key** | Gates transition from sealed → unsealed (mutations allowed) | Single key, Shamir shares, or auto-unseal via KMS — **operational, restart-frequency** |
| **Recovery keys** (optional) | Re-key / disaster recovery when master key must be rotated without data loss | Shamir or HSM M-of-N — **break-glass only** |

KNXVault v0.4.5 ships single unseal key (`KNXVAULT_UNSEAL_KEY`) and master key from env/file. Shamir, KMS auto-unseal, and HSM master wrap are backlog items.

## Decision

Adopt a **two-layer model** aligned with Vault semantics:

### 1. Master key — never Shamir-split

- The 32-byte master key decrypts persisted ciphertext only.
- **Custody options** (in priority order for production):
  1. Cloud or on-prem **KMS envelope wrap** at startup (**LT-14**, **LT-15**, future **LT-16**)
  2. **HSM-wrapped** master key material (**W31-03**)
  3. **Sealed Kubernetes Secret** or External Secrets Operator (near-term PoC/production pilot)
  4. Plain env/file — **dev and bootstrap only** when Raft disabled
- **Loss recovery:** encrypted backup restore + `POST /sys/rotate-master-key` ([W36-17](../product/tier-b-production.md)). Permanent loss without backup is acceptable documented risk ([ADR-0003](0003-envelope-encryption.md)).
- **No Shamir shares of the master key** in v1.x — avoids reconstructing the data key in memory during every unseal ceremony.

### 2. Unseal key — Shamir or auto-unseal

- Controls **operational seal state** only; does not replace the master key.
- **Options:**
  - Single `KNXVAULT_UNSEAL_KEY` (shipped)
  - **Shamir k-of-n** on the unseal key (**W41-05**)
  - **KMS auto-unseal** deriving or decrypting an unseal blob at process start (**LT-14**, **LT-15**) — decrypts/wraps unseal material, not a substitute for master key loading
- Shamir shares are **independent** of the master key (already enforced: unseal key must differ from master key when both set).

### 3. Dual-mode production posture (target)

When cloud KMS is available (**W41-14**):

- **Primary:** KMS auto-unseal for restarts (no human ceremony)
- **Break-glass:** Shamir unseal shares when KMS is unavailable or vault was manually sealed
- Master key still loaded via KMS wrap or sealed Secret — not via Shamir

### 4. HSM scope split

- **W31-02:** PKCS#11 for **PKI signing keys** (CA operations)
- **W31-03:** PKCS#11 or KMS for **master key wrap** (envelope root)
- Do not conflate the two — PKI HSM does not automatically protect the secrets master key.

### 5. Explicit non-goals (v1.x)

- Threshold cryptography / MPC (no full-key reconstruction avoidance beyond mlock/memzero)
- TEE / confidential-computing auto-unseal
- Shamir splitting of master key for daily unseal

## Consequences

### Positive

- Clear operator docs: “Shamir = who can unseal operations”, “KMS/HSM = where master key lives”
- Lower blast radius than splitting the master key for routine restarts
- Dual-mode path matches enterprise Vault expectations

### Negative

- Two custody workflows to document and audit
- KMS auto-unseal still deferred (LT-14/15); near-term relies on sealed Secrets

### Follow-up

| Item | Scope |
|------|-------|
| **W41-05** | Shamir on **unseal key** only |
| **W41-14** | Dual-mode KMS + Shamir break-glass |
| **W31-03** | HSM-wrapped master key |
| **LT-14**, **LT-15**, **LT-16** | KMS master key unwrap + auto-unseal |
| [PoC evaluation guide](../product/poc-evaluation-guide.md) | Combined posture for customers |

## References

- [Security model](../architecture/security-model.md)
- [ADR-0003](0003-envelope-encryption.md)
- [Backlog Tier I](../backlog.md#tier-i--enterprise-security--compliance-v10v12)