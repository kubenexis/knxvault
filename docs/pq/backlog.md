# PQ readiness backlog

Standalone backlog for post-quantum readiness. **IDs use `PQ-*`** so they do not collide with the main [docs/backlog.md](../backlog.md) `W*` items.

| Field | Meaning |
|-------|---------|
| **ID** | `PQ-0` phase umbrella or `PQ-##` work item |
| **Priority** | P0 (near-term) · P1 · P2 |
| **Status** | Not started · Partial · Complete |
| **Effort** | S · M · L · XL |
| **Depends on** | Other PQ-* or product prerequisites |

**Current focus:** **PQ-0** (document & classical harden) and design for **PQ-1** (agility / generations). Do not claim product “PQ-ready” until PQ-2+ transit and dual-plane gates agreed for target deployments.

Design background: [README](README.md), [roadmap](roadmap.md), [dual-crypto-planes](dual-crypto-planes.md), [crypto-generations](crypto-generations.md).

---

## Phase overview

| Phase | Theme | Exit criteria (summary) |
|-------|--------|-------------------------|
| **PQ-0** | Document & classical harden | Docs live; security model links; CA/TLS harden guidance; no false PQ claims |
| **PQ-1** | Agility & generations | `cryptoGeneration` / profile design implemented or accepted design; default g1; issuer naming |
| **PQ-2** | Hybrid transit | Edge or in-process hybrid TLS path for knxvault API; client matrix started |
| **PQ-3** | Dual PKI planes | platform-g1 + platform-g2 issuers; policy allow-list; Harbor remains g1 |
| **PQ-4** | PQ signatures | ML-DSA (or chosen) issue path for allow-listed apps; renew/rollover |
| **PQ-5** | Optional PQ KEM wrap | Only if policy requires hybrid KEK; not default |

---

## PQ-0 — Document and classical harden

| ID | Priority | Status | Effort | Title | Description | Acceptance |
|----|----------|--------|--------|-------|-------------|------------|
| **PQ-01** | P0 | Complete | S | PQ docs section | This `docs/pq/` tree: state, roadmap, dual-plane, generations, backlog | Linked from docs index + security model |
| **PQ-02** | P0 | Not started | S | Security model PQ stance | Explicit at-rest AES-256 vs non-PQ PKI/TLS in [security-model](../architecture/security-model.md) | Section + link to `docs/pq/` |
| **PQ-03** | P0 | Not started | S | Operator runbook pointer | Day-0/Day-2 mention crypto generations as future; Harbor stays classical | Short subsection or link |
| **PQ-04** | P0 | Not started | M | Classical PKI harden guide | Recommend RSA-4096 and/or ECDSA-P384 for new CAs; short leaf TTL; intermediate pattern | Doc + optional default tweak (non-breaking) |
| **PQ-05** | P0 | Not started | S | TLS harden checklist | TLS1.3-only at ingress; Raft mTLS; NetworkPolicy on unseal | Runbook checklist item |
| **PQ-06** | P0 | Not started | M | CA rollover drill | Practice dual CA / re-issue leaves (classical) as rehearsal for PQ migration | Drill notes in ops or lab |

---

## PQ-1 — Agility and generations

| ID | Priority | Status | Effort | Title | Description | Acceptance |
|----|----------|--------|--------|-------|-------------|------------|
| **PQ-10** | P1 | Not started | M | Design: CryptoGeneration | Formal field `cryptoGeneration: g1\|g2\|…`; map to CryptoProfile; default g1 | Design accepted in `docs/pq/` or ADR |
| **PQ-11** | P1 | Not started | M | Design: CertificateClass | StorageClass-like class → generation → issuer | Design + sample YAML |
| **PQ-12** | P1 | Not started | L | API/CRD algorithm + generation | Extend CA/issue/Certificate CRDs; keep RSA default | Issue RSA with explicit generation g1; old clients work |
| **PQ-13** | P1 | Not started | M | Issuer naming platform-g1 | Document/convention `ClusterIssuer/platform-g1`; Harbor samples use g1 | Samples + knxctl doc cross-link |
| **PQ-14** | P1 | Not started | M | Envelope alg version | Explicit version/alg id in envelope metadata for future AEAD | Old blobs still open; new seals versioned |
| **PQ-15** | P1 | Not started | S | Policy hooks (design) | Namespace allow-list for g2+; default deny PQ issue | Design + pseudo-policy |

---

## PQ-2 — Hybrid transit (TLS)

| ID | Priority | Status | Effort | Title | Description | Acceptance |
|----|----------|--------|--------|-------|-------------|------------|
| **PQ-20** | P1 | Not started | M | Edge hybrid TLS pattern | Document Envoy/ingress hybrid in front of knxvault; classical inner | Deploy guide + lab optional |
| **PQ-21** | P2 | Not started | L | Dual listener sketch | `:8200` classical / `:8201` hybrid when stack ready | Config flags; both health |
| **PQ-22** | P2 | Not started | XL | In-process hybrid KEM | When Go/OpenSSL hybrid is production-viable | Interop tests with chosen clients |
| **PQ-23** | P2 | Not started | M | Raft mTLS PQ plan | Single profile upgrade path; no dual Raft | Design only until peers ready |
| **PQ-24** | P1 | Not started | S | Client matrix (transit) | Track which clients support hybrid TLS | Table in docs/pq/ |

---

## PQ-3 — Dual PKI planes

| ID | Priority | Status | Effort | Title | Description | Acceptance |
|----|----------|--------|--------|-------|-------------|------------|
| **PQ-30** | P1 | Not started | L | Second CA + issuer g2 | Parallel classical g1 CA remains; g2 placeholder or ECDSA-strong | Two issuers; issue from both |
| **PQ-31** | P1 | Not started | M | Harbor pin g1 | knxctl/operator samples force Harbor Certificate to g1 | Harbor doc + sample |
| **PQ-32** | P1 | Not started | M | Allow-list enforcement | Reject g2 issue outside allow-listed namespaces | Unit/integration test |
| **PQ-33** | P2 | Not started | M | Dual trust bundle ops | Distribute ca-g1 vs ca-g2; optional combined | Runbook |
| **PQ-34** | P2 | Not started | L | Dual-issue optional | Two Secrets for one app during migration (rare) | Design + optional impl |

---

## PQ-4 — PQ signatures (issuance)

| ID | Priority | Status | Effort | Title | Description | Acceptance |
|----|----------|--------|--------|-------|-------------|------------|
| **PQ-40** | P2 | Not started | XL | OpenSSL/native PQ issue path | ML-DSA (or chosen) via provider; gated feature | Issue + verify with capable client |
| **PQ-41** | P2 | Not started | L | g2/g3 profile matrix | Publish algorithms per generation | Doc table + tests |
| **PQ-42** | P2 | Not started | M | Client matrix (certs) | Harbor, containerd, nginx, Go versions | Explicit “Harbor = g1 until …” |
| **PQ-43** | P2 | Not started | L | Migration runbook RSA→g2 | Rollover steps; rollback | Ops doc |

---

## PQ-5 — Optional PQ KEM key wrap

| ID | Priority | Status | Effort | Title | Description | Acceptance |
|----|----------|--------|--------|-------|-------------|------------|
| **PQ-50** | P2 | Not started | XL | Hybrid KEK wrap (optional) | Only if compliance demands PQ for key wrap; AES payload remains | Feature flag off by default; interop tests |
| **PQ-51** | P2 | Not started | M | Decision record | ADR: why AES wrap remains default | ADR accepted |

---

## Cross-cutting

| ID | Priority | Status | Effort | Title | Description | Acceptance |
|----|----------|--------|--------|-------|-------------|------------|
| **PQ-90** | P1 | Not started | S | Main backlog pointer | Link PQ backlog from [docs/backlog.md](../backlog.md) LT or residual section | Link present |
| **PQ-91** | P1 | Not started | M | Lab E2E g1 Harbor path | Cert from knxvault g1 → harbor-tls secret path (with knxctl process) | Documented lab or automated test |
| **PQ-92** | P2 | Not started | L | Lab E2E g2 opt-in app | Allow-listed app with g2 when available | Test green or explicit skip |
| **PQ-93** | P0 | Not started | S | Claim control | README/security: no “PQ-ready” until exit criteria | Grep clean of false claims |

---

## Suggested implementation order

```text
PQ-01 (docs) ✓
  → PQ-02, PQ-03, PQ-05, PQ-93
  → PQ-04, PQ-06
  → PQ-10, PQ-11, PQ-13, PQ-15 (design)
  → PQ-12, PQ-14 (code agility)
  → PQ-20, PQ-24, PQ-31
  → PQ-30, PQ-32
  → PQ-21–23, PQ-40+ as ecosystem allows
```

## Relationship to main backlog

| Main backlog | PQ |
|--------------|-----|
| W31-02 HSM | Orthogonal; can hold classical or later PQ keys |
| W34 mTLS | Classical mTLS now; PQ-2 extends transit |
| W30 operator | Certificate CRDs extended by PQ-12/PQ-30 |
| Envelope / crypto | PQ-14 versioning |

Do **not** duplicate full W* tables here; open PQ items when scheduling crypto work.

## Exit: “migration-ready” vs “PQ-ready”

| Label | Minimum |
|-------|---------|
| **PQ-aware / migration-ready** | PQ-0 complete + PQ-1 design accepted + default g1 + Harbor pin documented |
| **PQ-ready (limited)** | PQ-2 hybrid path for API + PQ-3 dual issuers + allow-listed g2 apps green |
| **PQ-ready (broad)** | PQ-4 client matrix includes target production apps; Harbor decision explicit (stay g1 or upgraded) |
