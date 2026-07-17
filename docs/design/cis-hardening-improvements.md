# Design: CIS-oriented hardening improvements

| Field | Value |
|-------|-------|
| **Status** | **P0–P3 implemented** (2026-07-17): kustomize/NetPol, metrics split, unseal CIDR, doctor prod, W64 stance + lease IDs, aes-kek auto-unseal, ACME egress sample |
| **Date** | 2026-07-17 |
| **Backlog** | **W75-*** (network + defaults), **W64** (soft multi-tenant), **W63** (custody) |
| **Related** | [production-security-posture.md](production-security-posture.md) · [security-model.md](../architecture/security-model.md) · CIS evaluation (session, 2026-07-17) |

---

## 1. Problem

CIS-style assessment graded knxvault ~**B / B+** overall, with three weak areas:

| Area | Grade | Gap |
|------|-------|-----|
| **Network segmentation** | B− | NetPol ingress-only; metrics on API port; unseal exposure ops-dependent |
| **Secure configuration defaults** | B− | Production profile strong **if set**; default remains lab-friendly |
| **Multi-tenant isolation** | C | Soft tenant mode; not CIS multi-tenant SaaS |

---

## 2. Goals

1. **Network:** Default-deny segmentation for API / metrics / Raft; unseal not world-reachable.  
2. **Defaults:** HA Raft installs run **production** profile unless explicit lab escape.  
3. **Multi-tenant:** Honest product stance — soft (same org) vs hard (separate vaults).

Non-goals: full Vault Enterprise namespaces; claiming SaaS isolation on one master key.

---

## 3. Target architecture (network)

```text
Clients ──► :8200 API (auth required)     ◄── ingress allowlist
Prom    ──► :8200/metrics or future :8201 ◄── monitoring allowlist + bearer
Peers   ──► :63001 Raft mTLS              ◄── knxvault pods only
Unseal  ──► :8200/sys/unseal              ◄── admin/jump only (NetPol); never public LB
```

Egress (later): default-deny + DNS, Raft, Valkey, allowlisted ACME/webhook/audit.

---

## 4. Phased plan

### P0 — **Shipped**

| Work | Detail | ID |
|------|--------|-----|
| Multi-node Raft forces production | Unless `lab` **and** `KNXVAULT_RAFT_ALLOW_INSECURE=true` | **W75-01** |
| Production kustomize | `deployments/k8s/production/` NetPol + config profile | **W75-02** |

### P1 — Network depth

| Work | ID |
|------|-----|
| Optional metrics listen address split | **W75-03** |
| Unseal source allowlist / admin-only NetPol sample | **W75-04** |
| Egress NetworkPolicy (DNS, Raft, Valkey, documented exceptions) | **W75-05** |
| `doctor --profile production` install gate | **W62-03** (existing) |

### P2 — Defaults & bootstrap

| Work | ID |
|------|-----|
| Bootstrap complete / root revoke | **W62-09–11** |
| Day-0 docs: production kustomize is primary path | **W75-06** |

### P3 — Multi-tenant

| Work | ID |
|------|-----|
| Product decision: soft vs hard isolation | **W64-00** |
| Soft tenant finish (lease IDs, quotas, fail-closed ns) | **W64-01–04** |
| Hard isolation runbook (one vault per trust domain) | **W75-07** |

### P4 — Custody (CIS enterprise tier)

| Work | ID |
|------|-----|
| KMS auto-unseal / master wrap | **W63-01–03** |

---

## 5. P0 behavior (implemented)

### 5.1 Raft-forces-production

In `ApplySecurityProfileDefaults`:

- If Raft enabled **and** peer count **> 1**:
  - If profile is empty/`lab` **and** `RaftAllowInsecure` is **false** → set profile to **`production`** and apply production defaults.
  - If profile is `lab` **and** `RaftAllowInsecure` is **true** → stay lab (explicit escape).
- Production validation still applies (TLS/ingress, metrics bearer, audit signing, etc.).

### 5.2 Production kustomize

Path: `deployments/k8s/production/`

- Bases parent `deployments/k8s/` resources.
- Patches ConfigMap: `KNXVAULT_SECURITY_PROFILE=production`, TLS termination ingress (typical behind ingress TLS).
- NetworkPolicy: default-deny style with explicit API (ingress), metrics scrape (monitoring), Raft peers, and **no** open world unseal.
- README: apply steps and required Secrets (audit signing, metrics bearer, unseal, master).

---

## 6. Multi-tenant product stance

| Stance | Use when | CIS SaaS multi-tenant? |
|--------|----------|------------------------|
| **Single trust domain** (default claim) | One platform/org | N/A |
| **Soft multi-tenant** | Many namespaces, same threat org | Partial after W64 |
| **Hard isolation** | Different customers/compliance | Separate knxvault per tenant (**W75-07**) |

Do **not** market soft mode as hard multi-tenant SaaS.

---

## 7. Acceptance criteria

### P0

- [x] Multi-node Raft without `RAFT_ALLOW_INSECURE` loads production profile by default  
- [x] Unit tests cover force + lab escape  
- [x] `deployments/k8s/production/` exists with NetPol + profile ConfigMap patch + README  
- [x] Design + backlog **W75-*** documented  

### Later

- [ ] Metrics port split  
- [ ] Egress NetPol  
- [ ] W64 soft tenant complete **or** W64-00 decline  

---

## 8. Related documents

- [production-security-posture.md](production-security-posture.md)  
- [deployments/k8s/production/README.md](../../deployments/k8s/production/README.md)  
- [operator-security.md](../operations/operator-security.md)  
