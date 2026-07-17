# Security posture assessment (honest baseline)

| Field | Value |
|-------|-------|
| **Status** | Baseline (internal engineering assessment) |
| **Date** | 2026-07-17 |
| **Audience** | Architects, security, maintainers |
| **Action plan** | [Production security posture design](../design/production-security-posture.md) · backlog **W62–W64** |
| **Not** | A sales claim, compliance certification, or pen-test report |

---

## 1. Scope

Assessment of knxvault as a **self-hosted secrets manager + private CA + Kubernetes TLS automation** (cert-manager-class operator), relative to:

- Production operability (“set and forget”)
- HashiCorp Vault Enterprise / HSM-class custody and multi-tenant SaaS
- Default cert-manager + Vault DIY stacks

Assumes current architecture: encrypt-before-Raft, in-process PKI, no loadable plugins, edge binaries (operator/CSI/ESO/webhook), formal audits through mid-2026.

---

## 2. Composite grades (agnostic)

| Dimension | Grade | Comment |
|-----------|-------|---------|
| Cryptographic design | **A−** | Strong patterns; custody not HSM |
| Application security (code) | **B+ / A−** | Audit culture + remediations; residuals remain |
| Identity & RBAC | **B+** | Broad methods; quality still ops-dependent |
| K8s / cert automation security | **B** | Right shape; ACME/webhook edge younger than cert-manager |
| Multi-tenant hard isolation | **C+** | Improving (W53); not finished for SaaS |
| Key management lifecycle | **B−** | Shamir + rotate exist; no enterprise KMS/HSM |
| Transparency / docs | **A** | Limits documented (ADRs, matrices, audits) |
| **Production set-and-forget** | **Medium** | Controls exist; many require operator discipline |
| **Composite (platform team vault)** | **~B+** | Smart if operated as designed |

---

## 3. What is handled smartly

- **Encrypt before Raft**; CA keys envelope-encrypted; distroless nonroot; OpenSSL CLI removed  
- **In-process PKI** (`crypto/x509`) — smaller RCE surface than shelling out  
- **No Vault-style plugins** — smaller TCB than arbitrary engine loading  
- **Edge split** (operator, CSI, ESO, webhook) with intent to use scoped tokens  
- **Auth breadth** with fail-closed patterns (TokenReview + Raft, seal path hardening, rate limit/lockout)  
- **PKI role enforcement** on CSR sign (audit-fixed class of bugs)  
- **ACME SSRF checks**; public LE rejects skip-TLS-verify  
- **Repeated formal audits** with fixes landed and residuals written down  

---

## 4. Gaps (honest)

### 4.1 Production set-and-forget — Medium

Many production controls are **optional or checklist-only**:

- Replace root token; NetworkPolicy for metrics/unseal  
- Raft mTLS; audit signing; TLS  
- Scoped policies for operator/CSI  

Misconfiguration undoes architecture. Example YAML still shows lab-leaning defaults in places (e.g. rate limit off in base example).

**Program:** [production-security-posture.md](../design/production-security-posture.md) §5 / **M-PRODSEC-1 (W62)**.

### 4.2 vs Vault Enterprise / HSM

| Area | Reality |
|------|---------|
| Custody | Env/file/K8s Secret master & unseal; software Shamir — not KMS/HSM root of trust |
| Plugins | Intentionally absent (security-positive for TCB; ecosystem uses webhooks) |
| Multi-tenant SaaS | Tenant mode partial; lease IDs not fully isolated (W53 residual) |
| Field pedigree | Younger than Vault; fewer years of CVE burn-in |

**Program:** custody **M-CUSTODY-1 (W63)**; multi-tenant only if product goal **W64**; ecosystem via M-DNS01-1 / external HTTP issuer — **not** plugin SDK.

### 4.3 vs cert-manager + Vault DIY

| When knxvault is better | When it is not |
|-------------------------|----------------|
| SA-auth operator, path-scoped policies, single product surface | Root token left on operator; anyone can create ClusterIssuer |
| No dual long-lived Vault tokens + cert-manager | Dual-run with weak AppRole/root never revoked |
| Documented multi-issuer without cert-manager controller | Lab flags / skipTLS / open webhookURL in prod |

Integration is a product advantage; **safety is not automatic** until Program C defaults land.

### 4.4 Other known limits

- Path/metadata cleartext in Raft ([ADR-0005](../adr/0005-cleartext-metadata-in-raft.md))  
- No PQ readiness claim ([docs/pq/](../pq/README.md))  
- ACME/DNS webhook surface still maturing (M-DNS01-1)  
- Metrics often unauthenticated unless operator hardens  

---

## 5. Comparison snapshots

### vs typical Vault OSS deploy

- **Simpler TCB** if knxvault scope fits; **weaker custody options** than mature auto-unseal/KMS ecosystems today.  
- Plugins: Vault more extensible and more dangerous if misused.

### vs cert-manager alone

- cert-manager is not a vault; knxvault **combines** vault + issuer (larger blast radius if poorly segmented, less token sprawl if SA auth is correct).  
- cert-manager has longer ecosystem/CVE history on pure TLS automation.

---

## 6. What we do about it

Full design and phases: **[production-security-posture.md](../design/production-security-posture.md)**.

| Gap | Milestone | Backlog |
|-----|-----------|---------|
| Set-and-forget Medium | **M-PRODSEC-1** | **W62-*** |
| Custody vs Vault Ent/HSM | **M-CUSTODY-1** | **W63-*** |
| Multi-tenant SaaS (optional) | product decision | **W64-*** |
| ACME webhook hardening | **M-DNS01-1** | **W61-*** (auth/allowlist) |

**Minimal five:** production profile fail-closed · production kustomize · root revoke + SA-only operator · doctor prod gate · KMS auto-unseal.

---

## 7. Explicit non-claims

Until acceptance criteria in the design doc are checked:

- Do **not** market “set and forget production vault.”  
- Do **not** claim Vault Enterprise / HSM parity.  
- Do **not** claim multi-tenant BFSI SaaS isolation.  
- Do claim **operator can replace cert-manager for private/self-signed/ACME** only within the [support matrix](../operations/certificate-support-matrix.md), with production posture applied.

---

## 8. Related

- [Security model](security-model.md)  
- [Production security posture design](../design/production-security-posture.md)  
- [Extensibility §9 (split / plugins)](../engineering/extensibility.md#9-do-we-need-to-split-knxvault-for-extensibility)  
- [Operator security checklist](../operations/operator-security.md)  
- Audit reports under [`docs/audit/`](../audit/)  
