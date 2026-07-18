<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security audit → backlog mapping — W86 (2026-07-17)

**Scope:** Full security audit of knxvault tip after W78–W85 (engine packs closed) and CLI CI/image work.  
**Verdict:** Core engine residual **Low–Medium**; default **Kubernetes custody / ESO edge** residual **Critical–High**.  
**Canonical backlog:** [`docs/backlog.md`](../backlog.md) § **Milestone W86**.  
**Related shipped packs:** W78–W85 audit remediations under [`docs/audit/`](.).

## Executive summary

| Layer | Assessment |
|-------|------------|
| Core vault (seal, crypto, PKI policy, KVv2 isolation, wrap CAS, SQL grant hardening) | Strong after W78–W85 |
| Default K8s deploy (operator RBAC, ESO, NetPol, Raft mTLS materials) | Weakest residual surface |
| Deploy recommendation | Ship with mitigations: production profile + production kustomize + isolate custody Secrets |

## Severity counts (open work)

| Severity | Count | Tracked as |
|----------|-------|------------|
| Critical | 1 | W86-01 |
| High | 6 | W86-02 … W86-07 |
| Medium | 15 | W86-08 … W86-22 |
| Low / Info | design residuals | W86-L\* / existing M-CUSTODY / ADR-0005 / PQ |

## DTP scope (base vs add-on)

| Backlog | DTP scope | Tag |
|---------|-----------|-----|
| **W86-01** | **base** (M-DTP-4) | `base` |
| **W86-02** | **base** (M-DTP-4) | `base` / `addon:operator` sample |
| **W86-03** | addon:operator | `addon:operator` |
| **W86-04** | addon:eso | `addon:eso` |
| **W86-05** | addon:eso | `addon:eso` |
| **W86-06** | **base** (M-DTP-4) | `base` |
| **W86-07** | **base** (M-DTP-4) | `base` |
| **W86-08…** | mixed engines/deploy | tag per finding |

## Critical → backlog

| Audit ID | Severity | Finding | Backlog | Area | DTP | Status |
|----------|----------|---------|--------|------|-----|--------|
| C1 | Critical | Operator SA can `get` all Secrets in `knxvault` NS, including master/unseal/root Secret | **W86-01** | k8s | **base** | **Complete** — no blanket Secret get; resourceNames exclude custody Secret `knxvault` |

## High → backlog

| Audit ID | Severity | Finding | Backlog | Area | DTP | Status |
|----------|----------|---------|--------|------|-----|--------|
| H1 | High | Operator Deployment optional-binds vault root token | **W86-02** | k8s | **base** | **Complete** — SA login only |
| H2 | High | Certificate Secret ownership accepts spoofable label (weakens W81-12) | **W86-03** | k8s | addon:operator | **Complete** — OwnerRef-only |
| H3 | High | ESO adapter cleartext HTTP vs HTTPS ClusterSecretStore | **W86-04** | k8s | addon:eso | **Complete** — TLS listen + HTTPS store |
| H4 | High | ESO `TokenFile` → unauthenticated shared vault proxy | **W86-05** | security | addon:eso | **Complete** — header required; TokenFile break-glass only |
| H5 | High | Production multi-node Raft mTLS required in code, not provisioned in overlays | **W86-06** | k8s | **base** | **Complete** — `knxvault-raft-tls` + STS mounts |
| H6 | High | Lab base NetPol: monitoring → full API :8200 (unseal co-resides) | **W86-07** | k8s | **base** | **Complete** — monitoring → :8201 only |

## Medium → backlog

| Audit ID | Severity | Finding | Backlog | Area |
|----------|----------|---------|---------|------|
| M1 | Medium | Lab security profile is process default (single-node set-and-forget) | **W86-08** | security |
| M2 | Medium | Unauth unseal; empty CIDR = allow all; prod examples still `/16` | **W86-09** | security |
| M3 | Medium | Login/unseal rate limits process-local (not Valkey-shared) | **W86-10** | security |
| M4 | Medium | Request signing optional in production | **W86-11** | security |
| M5 | Medium | Client-asserted ABAC headers (`X-KNX-Environment` / Cluster) | **W86-12** | auth |
| M6 | Medium | Webhook `caBundle` placeholder + plaintext escape hatch | **W86-13** | k8s |
| M7 | Medium | Ingress → :8200 includes `/sys/unseal` (path not filtered) | **W86-14** | k8s |
| M8 | Medium | Managed SQL allowlist: `CREATE TABLE AS SELECT`, `TO PUBLIC`, generic DDL | **W86-15** | security |
| M9 | Medium | ImportCA does not require IsCA / KeyUsageCertSign | **W86-16** | crypto |
| M10 | Medium | Managed DB admin URL allows `sqlite:` / `file:` | **W86-17** | security |
| M11 | Medium | Vault-compat mount ACL ≠ CA isolation (role→CA only) | **W86-18** | auth |
| M12 | Medium | Operator ClusterRole cluster-wide leases | **W86-19** | k8s |
| M13 | Medium | Operator metrics `:8080` without auth/NetPol sample | **W86-20** | k8s |
| M14 | Medium | Multi-binary production image includes CLI (TCB size) | **~~W86-21~~ Complete** — CLI removed from Dockerfile; CI host artifact only | security |
| M15 | Medium | Operator code default vault `http://…` (manifest HTTPS overrides) | **W86-22** | k8s |

## Low / design residual (tracked, not P0)

| Item | Tracking |
|------|----------|
| Seal does not wipe master key (API fence) | M-CUSTODY-1 / W63; design residual |
| Auto-unseal KEK + ciphertext collocation | W63 / ops runbook |
| Soft multi-tenant / cleartext Raft metadata | ADR-0005 / W64 |
| Non-PQ classical crypto | [`docs/pq/backlog.md`](../pq/backlog.md) |
| OCSP unauth crypto (rate-limited + body cap) | **W86-L01** P2 |
| Transit multi-node rotate LWW | **W86-L02** P2 |
| Envelope Seal without path AAD | **W86-L03** P2 |
| OpenAPI/swagger unauthenticated | **W86-L04** P2 |

## Already complete (do not re-open)

W78–W85 remediations (pathLenZero, unseal breadth, wrap CAS, SQL normalize/membership, ImportCA RSA floor, KVv2 reserved paths, TokenReview audiences, etc.) remain **Complete**. See individual `security-remediation-w*.md` reports.

## Implementation order (suggested)

1. **W86-01** → **W86-02** (custody isolation)  
2. **W86-04** → **W86-05** (ESO edge)  
3. **W86-06**, **W86-07**, **W86-13**, **W86-14** (deploy plane)  
4. **W86-03** (Certificate Secret ownership)  
5. **W86-15** → **W86-17** → **W86-16** (engines)  
6. Remaining Medium / Low  

## Verify after implementation

```bash
make quality
make clean all
# Policy: operator SA cannot get secret/knxvault; ESO requires TLS+auth; production overlay has Raft mTLS mounts
```
