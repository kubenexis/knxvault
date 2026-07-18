<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Design: Phase A/B/C hardening and capability placement

| Field | Value |
|-------|-------|
| **Status** | **Accepted** (implemented) |
| **Date** | 2026-07-18 |
| **Branch** | `knxvault-distributed-trust-platform` |
| **Related** | [DTP](distributed-trust-platform.md) · [AGENTS.md](../../AGENTS.md) N1–N5 · [W86 audit](../audit/security-audit-w86-backlog-2026-07-17.md) |

---

## 1. Goals

After M-DTP-0…4, grow **capability** without expanding the **custody TCB**:

| Phase | Name | Outcome |
|-------|------|---------|
| **A** | Lock the base | Unseal plane hygiene, Ingress deny unseal, base Day-0/1 ops |
| **B** | Harden add-ons | W86-03 OwnerRef-only; W86-04/05 ESO TLS+auth; W86-13 webhook caBundle path |
| **C** | Capability on the right plane | Platform-edge golden path; engines/federation/ACME placement docs |

---

## 2. Phase A — Base lock

| Item | Implementation |
|------|----------------|
| Unseal CIDR examples ≤ jump/pod ranges | `production/configmap-patch.yaml`, `config/knxvault.production.yaml` (W86-09) |
| Ingress must not expose `/sys/unseal` | `production/ingress-api-no-unseal.yaml` (W86-14) |
| Default surface remains base-only | Existing `make dtp-surface` + AGENTS.md |
| Operator samples | No root token; Secrets Role without blanket get (W86-01/02) |

---

## 3. Phase B — Add-on hardening

| Item | Implementation |
|------|----------------|
| **W86-03** | `secretOwnedByCertificate` OwnerRef-only; refuse label spoof |
| **W86-04** | ESO `ListenAndServe` TLS required; deploy mounts `knxvault-eso-tls`; port 8443 HTTPS |
| **W86-05** | TokenFile ignored unless `AllowTokenFileProxy`; unauthenticated fetch → 401 |
| **W86-13** | Webhook TLS template + caBundle Day-0 steps in platform-edge ops |
| **W86-22** | Operator default `KNXVAULT_ADDR` is `https://…` |

---

## 4. Phase C — Capability placement

| Capability | Plane |
|------------|--------|
| Seal, Raft, critical KV, private CA | Base |
| CSI / webhook / ESO | Platform-edge add-ons |
| Public OIDC/LDAP | Edge gates |
| Public ACME/LE | Public TLS edge + operator ACME flag |
| Transit / wrap / leases / identity | In-tree base API + RBAC |
| HSM auto-unseal | Base (M-CUSTODY-1 — separate program) |

Docs: [base-day0-day1.md](../operations/base-day0-day1.md), [platform-edge-day0-day1.md](../operations/platform-edge-day0-day1.md).

---

## 5. Non-goals

- Microservices split of sealed core (**N4**)
- Multi-tenant SaaS isolation in one process (**N2**)
- Enabling all components on default production (**N5**)

---

## 6. Verification

```bash
make quality all
make dtp-surface
go test ./internal/eso/ ./internal/operator/controllers/ -count=1
```
