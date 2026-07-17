<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Design: Production security posture (set-and-forget, custody, safer defaults)

| Field | Value |
|-------|-------|
| **Status** | **Partial** — **A1 production security profile shipped** (W62-01/02/04); A2–A6 / W62-03+ remaining |
| **Date** | 2026-07-17 |
| **Milestone** | **M-PRODSEC-1** — production profile + safe defaults (backlog **W62-***) |
| **Follow-on** | **M-CUSTODY-1** (KMS/HSM — **W63-***); multi-tenant SaaS only if product goal (**W64-***); CIS network/defaults **W75-*** ([cis-hardening-improvements.md](cis-hardening-improvements.md)) |
| **Related** | [Security model](../architecture/security-model.md) · [Operator security](../operations/operator-security.md) · [Extensibility](../engineering/extensibility.md) · [DNS-01 design](dns01-providers-and-webhooks.md) · [HLD](../architecture/hld.md) |

---

## 1. Problem statement

An internal security assessment of knxvault as a **vault + CA + cert-manager-class** product concluded:

| Dimension | Assessment | Gap |
|-----------|------------|-----|
| Cryptographic design | Strong | Custody not HSM/KMS-backed |
| Application security | Strong (audits + remediations) | Residuals remain |
| **Production “set and forget”** | **Medium** | Many controls exist but **depend on operator discipline** (policies, NetworkPolicy, no root token, Raft mTLS, …) |
| **vs Vault Enterprise / HSM** | Behind on custody; intentionally not plugin-parity | Need **outcomes** (custody, isolation), not Vault plugins |
| **vs cert-manager + Vault DIY** | Better integrated **if** recommended posture is used | **Not automatically safer** if root tokens / open ClusterIssuers remain |

This document turns that assessment into an **actionable design and backlog**. It does **not** claim the product is “set and forget” or “Vault Ent parity” until the acceptance criteria below are met.

---

## 2. Goals

### 2.1 Goal A — Production set-and-forget (encode discipline)

**Success:** A cluster installed with the **production security profile** cannot start with lab flags, missing TLS (or unstated trust), multi-node Raft without mTLS, unauthenticated metrics, or perpetual root. Day-0 ends with **scoped admin + operator SA**, not root forever. Network/RBAC baselines ship as **apply-once manifests**. `doctor` **fails** (not warn-only) on critical posture gaps in prod mode.

### 2.2 Goal B — Close real gaps vs Vault Ent / HSM (outcomes)

**Success:** Disk/etcd dump without KMS/HSM IAM is not enough to recover master material; multi-tenant isolation is either **honestly out of scope** (single trust domain) or completed for SaaS; ecosystem grows via **webhooks / external HTTP issuers**, not loadable plugins.

### 2.3 Goal C — Integrated path safer by default

**Success:** Recommended install **cannot** be “root token + anyone creates ClusterIssuer.” Operator is SA-only in production; Issuer RBAC and webhook allowlists are defaults; dual-run cert-manager tokens are revoked as part of migration.

---

## 3. Non-goals

| Non-goal | Rationale |
|----------|-----------|
| HashiCorp Vault **plugin SDK** parity | Expands TCB; see [extensibility](../engineering/extensibility.md) §9 |
| Microservices split of the sealed core “for security” | Usually more surface; keep one crypto/Raft TCB |
| Claiming set-and-forget **without** KMS/auto-unseal | Restarts still need humans or static secrets |
| Claiming multi-tenant SaaS without W64 | Lease/metadata residuals (W53) still matter |
| Full cert-manager ecosystem (every DNS provider, Venafi, …) | Webhook + curated in-tree only |

---

## 4. Target architecture

```text
┌─────────────────────────────────────────────────────────────┐
│  security.profile = production (fail-closed ValidateSecurity)│
│  knxvault-server TCB: seal · master · Raft · auth · PKI     │
└─────────────┬───────────────────────────────┬───────────────┘
              │ SA + path policies only         │ DNS-01 HTTP + auth
              ▼                                 ▼
     operator / CSI / ESO              out-of-tree webhooks
     (no root in prod samples)         (allowlisted URLs)
              │
              ▼
     production kustomize: NetworkPolicy, Issuer RBAC,
     metrics bearer, bootstrap-complete (root dead)
              │
              ▼ (M-CUSTODY-1)
     KMS auto-unseal + optional master wrap / PKCS#11
```

**Principles**

1. **Safe by default** in `production` profile; lab remains explicit.
2. **Privilege reduction at edges** (already started) — never master key in operator/CSI/webhook.
3. **Contracts over plugins** for third parties (DNS-01, future external issuer).
4. **One sealed data plane** — no core microservice split for this program.

---

## 5. Program A — Production set-and-forget

### 5.1 Security profile — **shipped (A1)**

```yaml
# config / env
security:
  profile: lab | production   # KNXVAULT_SECURITY_PROFILE
  tls_termination: server | ingress
```

Implementation: `internal/config` — `ApplySecurityProfileDefaults` + `ValidateSecurity` production branch; example `config/knxvault.production.yaml`.

**When `production` (fail closed at startup via extended `ValidateSecurity`):**

| Rule | Behavior | Status |
|------|----------|--------|
| Multi-node Raft | Peer mTLS **required** (`RaftAllowInsecure` rejected); counts peers from `InitialMembers` **or** `InitialMembersRaw` | **Done** |
| `k8s_auth_insecure` / dev JWT secret | **Reject** | **Done** |
| Public ACME + `skipTLSVerify` | **Reject** for public LE (existing ACME client); full Issuer admission later (Program C / W61) | Partial (ACME path) |
| Server TLS | **Required**, *or* `tls_termination: ingress` | **Done** |
| Rate limit | **Forced on** | **Done** |
| Metrics | Bearer **required** | **Done** |
| Audit signing key | **Required** | **Done** |
| Root token | TTL **capped at 4h** (bootstrap gate §5.2 / W62-10 still open) | **Partial** |
| Unseal ≠ master | Keep existing Raft rule | **Done** (pre-existing) |
| Valkey (if set) | `rediss://` / credentials / unix socket | **Done** |
| `RequireHTTPSClients` / RBAC fail-closed | Forced on | **Done** |

Artifacts:

- [x] `config/knxvault.production.yaml`
- [ ] `deployments/k8s/production/` (kustomize overlay) — A3 / W62-05
- [x] Unit tests: bad envs fail `ValidateSecurity`

### 5.2 Bootstrap → root death

| Step | Behavior |
|------|----------|
| First start | Root (or one-time bootstrap token) allowed for setup only |
| Prod default root TTL | Short (e.g. **1–4h**), non-renewable preferred |
| Complete | `POST /sys/bootstrap/complete` (or install Job) **revokes root** after scoped admin + operator role exist |
| Ongoing | Operator/CSI/ESO use **K8s SA → TokenReview → path policies only** |
| Doctor | **Fail** if root still valid past bootstrap window in production profile |

### 5.3 Production pack manifests

Under `deployments/k8s/production/` (or equivalent):

| Artifact | Purpose |
|----------|---------|
| NetworkPolicy | Limit who can reach API, metrics, unseal paths |
| Metrics hardening | Bearer and/or separate port |
| Operator SA + Role | `pki/*` / issue paths — **not** `*` |
| Issuer RBAC | Only platform namespace/group may create `KNXVaultClusterIssuer` |
| Pod hardening | nonroot (already), RO rootfs / seccomp where practical |
| Secret templates | Master + unseal **placeholders** for sealed-secrets / ESO — never real values in Git |

### 5.4 Doctor / posture gate

`knxvault-cli doctor --profile production` (and optional operator Ready condition):

| Check | Prod severity |
|-------|----------------|
| Sealed / Raft not ready | fail |
| TLS / termination mode unset | fail |
| Root still active after bootstrap | fail |
| Insecure flags present | fail |
| Multi-node Raft without mTLS | fail |
| Audit signing unset | fail |
| Metrics unauthenticated | fail (or warn→fail) |
| Default SA with `*` admin | warn→fail |

**Install done** = `doctor --profile production` reports `fail:0`.

### 5.5 Config default hygiene

- Example/production YAML: rate limit **on**, insecure flags **off**.
- Align `config/knxvault.example.yaml` comments so “copy-paste prod” does not ship lab defaults silently.

### 5.6 Auto-unseal (ops set-and-forget)

Without automated unseal, set-and-forget remains partial after every restart.

| Option | Notes |
|--------|-------|
| **KMS auto-unseal** (Program B) | Preferred — unseal material not long-lived plain Secret |
| K8s Secret mount + strict RBAC | Automates ops; weaker custody |

---

## 6. Program B — Custody, isolation, ecosystem (vs Vault Ent)

### 6.1 External custody (M-CUSTODY-1)

| ID theme | Deliverable |
|----------|-------------|
| KMS auto-unseal | Unwrap unseal secret via cloud KMS / similar at start |
| KMS-wrapped master | Master at rest is ciphertext; process unwraps with KMS/PKCS#11 |
| PKCS#11 CA keys | Optional offline root / intermediate (HLD deferred → promote when needed) |
| Runbooks | Dual control, share ceremony + KMS IAM separation |

**Success bar:** PVC/etcd dump without KMS IAM credentials does not yield usable master material.

Suggested order: **auto-unseal → master wrap → HSM for offline root**.

### 6.2 Multi-tenant SaaS (optional product decision)

**Default product stance:** single trust domain / platform vault. Document “one vault per classification level” (ADR-0005).

Only if SaaS multi-tenant is a goal (**W64**):

- Tenant-prefix **all** handles (leases, etc. — close W53 residual)
- Per-tenant quotas; hard cross-tenant deny
- Optional per-tenant cluster mode for true isolation
- Tenant-scoped audit export

### 6.3 Ecosystem without plugins

| Need | Mechanism |
|------|-----------|
| DNS providers | M-DNS01-1 webhook v1 + templates |
| Extra secret backends | Curated in-tree engines or out-of-process fetchers with scoped tokens |
| Enterprise public CA | Future **HTTP external issuer** (not `.so` plugins) |
| Policy-as-code | Existing simulate/HCL; OPA only if required (LT) |

**Explicitly not near-term (product decision 2026-07-17):**

| Capability | Backlog | Near-term substitute |
|------------|---------|----------------------|
| Cloud IAM secret engines (AWS / Azure / GCP) | **LT-02** | KV + database + SSH dynamic engines |
| Cloud auth methods (AWS IAM, Azure MSI, GCP) | **LT-15** | Kubernetes SA, AppRole, OIDC / JWT |

### 6.4 Battle-hardening (pedigree)

- Permanent regression tests for past Critical/High findings
- Security disclosure process + supported versions
- Soak/chaos: seal, Raft kill, ACME renew
- Optional third-party pen test: **operator + ACME + CSI**

---

## 7. Program C — Safer than DIY by default

### 7.1 Operator never root (production)

| Change | Detail |
|--------|--------|
| Samples | Root-token operator mode **lab-only** |
| Production | Require `KNXVAULT_K8S_ROLE` + TokenReview; fail if profile=production and static root |
| Bootstrap Job | Creates role `operator` with pki/issue paths only |
| CSI / ESO | Separate read-scoped roles per app prefix |

### 7.2 ClusterIssuer is privileged

| Change | Detail |
|--------|--------|
| Admission or controller policy | ACME `webhookURL` allowlist; reject unsafe skipTLS |
| RBAC | ClusterIssuer create limited to platform group |
| Default apps | Namespaced `Issuer`; ClusterIssuer rare |
| M-DNS01-1 | Webhook bearer/mTLS so URL leak ≠ open DNS write |

### 7.3 Certificate delivery

- Prefer CSI / `delivery: None` examples where apps can mount
- Where TLS Secret required (Ingress): short-lived leaves + renewBefore; document etcd key risk
- Integration notes for sealed-secrets / KMS for Secrets

### 7.4 Migration without dual-weaken

- Revoke cert-manager Vault long-lived tokens when operator takes over
- Dual-run Vault profile: short TTL AppRole, `pki/sign/*` only
- Optional doctor warn if both stacks issue same domains

### 7.5 Golden path (single narrative)

```text
production profile
  → Raft 3 + mTLS
  → unseal (KMS or t-of-n shares)
  → bootstrap complete (root dead)
  → apply operator with SA role
  → apply NetworkPolicy + Issuer RBAC
  → doctor --profile production (fail:0)
  → first ClusterIssuer from platform ns only
```

Anything else is lab/advanced.

---

## 8. Phased delivery

### Phase 0 — M-PRODSEC-1 (high ROI)

| # | Work | Closes |
|---|------|--------|
| 1 | `security.profile=production` + `ValidateSecurity` | Set-and-forget |
| 2 | Production kustomize (NetPol, metrics, Issuer RBAC) | DIY footguns |
| 3 | Operator samples SA-only; root lab-only | Goal C |
| 4 | `doctor --profile production` fail-closed | Install gate |
| 5 | Example default hygiene (rate limit, etc.) | Misconfig |
| 6 | Bootstrap complete / root revoke + short prod root TTL | Goal A/C |

**Exit:** Prod install rejects unsafe config; Day-0 cannot “finish” with live root + open metrics in production profile.

### Phase 1 — M-CUSTODY-1

| # | Work |
|---|------|
| 7 | KMS auto-unseal (one provider first) |
| 8 | KMS-wrap master key |
| 9 | Custody runbooks + break-glass |

**Exit:** Honest enterprise custody narrative for at least one KMS.

### Phase 2 — ACME / Issuer attack surface

| # | Work |
|---|------|
| 10 | M-DNS01-1 webhook auth + allowlist (align W61) |
| 11 | Validating policy on Issuer fields |
| 12 | SSRF / CR-abuse e2e tests |

### Phase 3 — Multi-tenant SaaS (optional)

| # | Work |
|---|------|
| 13–15 | W64 lease isolation, quotas, audit-by-tenant |

### Phase 4 — Optional HSM / external issuer

| # | Work |
|---|------|
| 16 | PKCS#11 offline root/intermediate |
| 17 | HTTP external issuer (Venafi-class) |

---

## 9. Minimal five (if capacity is tiny)

1. `security.profile=production` fail-closed  
2. Production kustomize (NetworkPolicy + metrics + Issuer RBAC)  
3. Bootstrap complete / root revoke + operator SA-only  
4. `doctor --profile production` as install gate  
5. KMS auto-unseal (first real custody leap)  

---

## 10. Mapping assessment → programs

| Assessment gap | Program | Achieved when |
|----------------|---------|---------------|
| Set-and-forget **Medium** | A (+ B auto-unseal) | Unsafe config fails closed; restarts don’t need a human checklist (with KMS) |
| Behind Vault Ent / HSM | B | Custody + optional isolation; ecosystem via contracts |
| DIY only safer if expert | C | Default install cannot be root + open ClusterIssuer |

---

## 11. Security concerns (summary)

Encoding discipline reduces **operational** risk; it does not remove:

- K8s admin == vault admin unless separate trust domains
- ACME/DNS webhook blast radius if Issuer create is wide
- Cleartext metadata in Raft (ADR-0005)
- Process-memory master key until KMS/HSM wrap

Threat model baseline: [security model](../architecture/security-model.md). Split/plugin analysis: [extensibility §9](../engineering/extensibility.md#9-do-we-need-to-split-knxvault-for-extensibility).

---

## 12. Acceptance criteria (milestone level)

### M-PRODSEC-1

- [ ] `KNXVAULT_SECURITY_PROFILE=production` rejects documented lab/insecure combinations  
- [ ] `deployments/k8s/production/` applies NetPol + Issuer RBAC + metrics bearer  
- [ ] Bootstrap path revokes or expires root; operator production samples use SA only  
- [ ] `doctor --profile production` fails on root-alive, no-TLS, no-Raft-mTLS, no audit signing  
- [ ] Docs: single golden-path Day-0; lab paths explicitly labeled  
- [ ] Unit/integration tests cover ValidateSecurity + doctor prod profile  

### M-CUSTODY-1

- [ ] At least one KMS auto-unseal path documented and tested  
- [ ] Master wrap or documented interim + roadmap to wrap  
- [ ] Break-glass and key ceremony runbook  

### Optional W64

- [ ] Product decision recorded (single-tenant vs SaaS)  
- [ ] If SaaS: lease/handle tenant isolation + quotas  

---

## 13. Related documents

| Document | Role |
|----------|------|
| [Security model](../architecture/security-model.md) | Threats and controls today |
| [Operator security](../operations/operator-security.md) | Checklist this program automates |
| [Extensibility](../engineering/extensibility.md) | Why not plugins; edge split |
| [DNS-01 providers](dns01-providers-and-webhooks.md) | Webhook auth/allowlist (W61) |
| [Backlog](../backlog.md) | **W62-***, **W63-***, **W64-*** |
| [Envelope encryption](../architecture/envelope-encryption.md) | Master key lifetime |
| [ADR-0005](../adr/0005-cleartext-metadata-in-raft.md) | Metadata cleartext tradeoff |
