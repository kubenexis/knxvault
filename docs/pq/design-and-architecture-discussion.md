# Design and architecture discussion — post-quantum readiness

Narrative record of the architecture discussion that led to the PQ docs set, dual crypto planes, crypto generations, and the [PQ backlog](backlog.md). This is a **design discussion**, not a completed implementation.

| Field | Value |
|-------|-------|
| **Date** | 2026-07-16 |
| **Status** | Discussion / direction — product remains classical |
| **Audience** | Architects, security, maintainers |
| **Related** | [README](README.md) · [current-state](current-state.md) · [roadmap](roadmap.md) · [dual-crypto-planes](dual-crypto-planes.md) · [crypto-generations](crypto-generations.md) · [backlog](backlog.md) |

---

## 1. Starting question

**Is KNXVault post-quantum ready?**

**Conclusion:** **No.** The product uses classical cryptography. The discussion then shifted from a yes/no claim to:

1. What is already relatively strong under quantum assumptions?  
2. What is the real risk (especially harvest-now / decrypt-later)?  
3. How do we improve readiness **without** breaking Kubernetes integrations (e.g. Harbor)?  
4. Can classical and PQ-capable applications coexist behind one abstraction?

---

## 2. Current building blocks (baseline)

The platform’s crypto surface was inventoried as follows:

| Building block | Implementation today | PQ note |
|----------------|----------------------|---------|
| Secrets at rest (envelope) | AES-256-GCM + random DEKs | Symmetric; relatively durable if keys are strong |
| Master / DEK wrapping | AES-256-GCM with master key | Same family; custody matters more than algorithm swap |
| PKI (CA / leaves) | RSA (typ. 2048+) OpenSSL / native | **Not PQ** (Shor) |
| TLS (API / Raft mTLS) | Classical TLS 1.3; certs typically RSA | **Not PQ** for handshake and classical certs |
| Unseal / Shamir | Symmetric secret + shares | Not a public-key PQ problem |
| Tokens / HMAC audit | Opaque / HMAC | Symmetric |

**Important architectural point:** applications such as Harbor **never see envelope crypto**. They only consume **X.509 certificates and TLS**. So at-rest AES work does not change Harbor integration; **certificate and TLS algorithm changes do**.

---

## 3. How to improve each layer (discussion)

### 3.1 Envelope and master/DEK wrap (AES-256)

**Direction:** Keep AES-256-GCM as the bulk and wrap algorithm. Do not replace data encryption with a KEM.

Improvements discussed:

- Strong master entropy only (no passphrase KDF — already the model).  
- Document Grover vs Shor honestly.  
- **Format versioning** so a future AEAD can be introduced without a flag day.  
- Proven master-key rotation and re-encrypt (already part of the product story).  
- Optional later hybrid KEK wrap only if compliance demands it (backlog PQ-5).

### 3.2 PKI (RSA today)

**Direction:** Classical harden first, then **algorithm agility**, then dual CA / PQ signatures.

Stages discussed:

| Stage | Intent |
|-------|--------|
| Classical harden | RSA-4096 and/or ECDSA-P384, short leaf TTL, intermediate online |
| Agility | Explicit algorithm / generation on CA and issue paths; stop hard-coding RSA-only forever |
| Dual PKI | Parallel classical and PQ (or hybrid) CA trees |
| PQ signatures | ML-DSA (or chosen) for allow-listed apps when clients support them |

**Migration insight:** PQ is a **CA rollover problem**, not a single config flip. Dual-run of trust anchors is mandatory.

### 3.3 TLS (API + Raft)

**Direction:** Biggest harvest-now risk. Prefer **edge hybrid TLS** or dual listeners before forcing PQ inside every client.

| Pattern | Pros | Cons |
|---------|------|------|
| Edge proxy hybrid → knxvault classical | Fast; Harbor unaffected | Trust in mesh/gateway |
| Dual listener (`:8200` / `:8201`) | Clear opt-in | Ops complexity |
| In-process hybrid KEM | Clean long-term | Depends on Go/OpenSSL maturity |
| One Raft mTLS profile | Keeps consensus simple | Peers upgrade together |

**Consensus:** Do **not** invent two Raft clusters solely for classical vs PQ.

---

## 4. Backward compatibility and Harbor / K8s

### 4.1 Will PQ work break integrations?

| Change | Breaks Harbor / legacy K8s? |
|--------|----------------------------|
| Keep AES-256 envelopes | **No** |
| Default classical certs (g1) | **No** |
| RSA-4096 / ECDSA classical re-issue | Usually **no** (test once) |
| Force PQ leaf into `harbor-tls` | **Likely yes** |
| Hybrid only on knxvault admin API | Harbor **unaffected** |
| Global “PQ default” | **Yes** — avoid |

### 4.2 What Harbor actually consumes

```text
Harbor chart: certSource: secret → Secret tls.crt/tls.key
Harbor does not call knxvault “generations” or choose algorithms.
```

Compatibility strategy in one line:

> **Never change what Harbor mounts until that algorithm is proven on Harbor; improve knxvault at rest and put PQ on opt-in planes first.**

---

## 5. Dual-stack architecture (classical + PQ apps)

### 5.1 Problem statement

Need both:

- Applications that **only** speak classical TLS/certs (Harbor, older images).  
- Applications that **can** use hybrid/PQ when ready.

A single “upgrade everyone” switch was rejected.

### 5.2 Solution shape: two planes, one platform

```text
                    knxvault (one Raft, one AES store, one authz)
                            │
          ┌─────────────────┴─────────────────┐
          ▼                                   ▼
   Classical plane                      PQ / hybrid plane
   (default)                            (opt-in)
```

**Shared:** cluster, policies, audit, envelope encryption.  
**Split:** CA/issuer trees, workload cert Secrets, optional API TLS termination.

### 5.3 Abstraction layers (discussed)

| Layer | Role |
|-------|------|
| **Crypto profile** | Concrete algorithms + TLS settings (platform-owned) |
| **Trust domain / issuer** | `platform-g1` vs `platform-g2` ClusterIssuers |
| **Policy** | Who may request which plane (namespace allow-list, RBAC) |
| **CertificateClass** (optional) | StorageClass-like name so apps never name algorithms |
| **API serve profile** | Classical listener and/or hybrid edge / second port |

Apps bind to **issuer / class / generation**, not to raw crypto parameters.

### 5.4 What the abstraction must not hide

- **Which plane** a workload is on (must be explicit enough that Harbor stays classical).  
- **Whether the runtime supports** that plane (property of the app/OS stack).

Hiding plane selection completely would assign PQ certs to legacy apps and cause outages.

---

## 6. Crypto generations (g1 / g2 / g3)

### 6.1 Proposal

Name platform contracts:

| Generation | Intent |
|------------|--------|
| **g1** | Legacy-safe: today’s K8s/Harbor clients |
| **g2** | PQ-aware transit and/or hybrid identity |
| **g3** | Stricter PQ signatures when matrix allows |

Use **g1, g2, g3** in APIs. Treat “gx” only as informal “future generation” language in design text.

### 6.2 Why this was favored

- Stable contract while algorithms under a generation evolve carefully.  
- Natural dual-stack: default **g1**, opt-in **g2+**.  
- Operable migration language (“move service X to g2”).  
- Aligns with multi-issuer style already in the product.

### 6.3 Risks called out

- Silent breaking change inside g1 → prefer new generation or dual-run.  
- Too many generations → keep few live.  
- Confusion with Kubernetes `metadata.generation` → use `cryptoGeneration` or a dedicated label.  
- Vague `gx` in product config → avoid.

### 6.4 Mapping chain (agreed mental model)

```text
cryptoGeneration → CryptoProfile → Issuer/CA → Certificate → Secret → workload
```

---

## 7. “How does Harbor call g1 or g2?”

### 7.1 Answer

**It doesn’t.** Harbor is a **dumb TLS consumer**.

### 7.2 Who chooses

| Actor | Action |
|-------|--------|
| Platform / knxctl / GitOps | Pins Harbor’s certificate to **g1** |
| knxvault-operator | Issues PEM into `harbor-tls` from `platform-g1` |
| Harbor | Loads Secret only |

```yaml
# Platform decision — Harbor never sees cryptoGeneration
spec:
  secretName: harbor-tls
  cryptoGeneration: g1
  issuerRef: { name: platform-g1, kind: KNXVaultClusterIssuer }
```

```yaml
# Harbor chart remains generation-agnostic
expose.tls.certSource: secret
expose.tls.secret.secretName: harbor-tls
```

### 7.3 Implication for knxctl primary-cluster

Stack process (documented outside this repo under knxctl-v3) should encode:

- knxvault before Harbor  
- Certificate for Harbor always **g1**  
- Preflight: Secret exists; not “Harbor asked for g2”

---

## 8. Suggested way forward (synthesis)

### Principles

1. Keep **AES-256-GCM** envelopes and DEK wrap.  
2. Default plane **g1** for all existing K8s integrations.  
3. **Dual planes** + **generations** as the product abstraction.  
4. **Hybrid transit** at edge or second listener before pure PQ certs everywhere.  
5. **PQ signatures** only for allow-listed apps; Harbor last and only when proven.  
6. One Raft; one envelope store.  
7. Honest product language: migration-ready before PQ-ready.

### Phased program

| Phase | Theme |
|-------|--------|
| PQ-0 | Document & classical harden |
| PQ-1 | Agility: generations, profiles, CRD fields, default g1 |
| PQ-2 | Hybrid transit (edge first) |
| PQ-3 | Dual PKI issuers; policy allow-list; Harbor pin g1 |
| PQ-4 | PQ issue path when OpenSSL/Go/clients ready |
| PQ-5 | Optional hybrid KEK wrap if required |

Work items: [backlog.md](backlog.md).

### Minimal viable dual-stack (near term)

Even before real PQ algorithms ship:

1. One knxvault, AES unchanged.  
2. Classical CA/issuer branded **g1** / `platform-g1`.  
3. Certificate (or class) field/convention for generation.  
4. Harbor samples and knxctl path **hard-pin g1**.  
5. Placeholder **g2** issuer name and allow-list policy design.  
6. Optional hybrid edge for knxvault API only.

That delivers the **abstraction and safety interlock** before the crypto is fully available.

---

## 9. Decisions and non-decisions

### Agreed direction

| Topic | Direction |
|-------|-----------|
| At-rest crypto | Stay AES-256-GCM; version for agility |
| Dual-stack | Yes — planes + generations + policy |
| Harbor | Always classical g1 until explicit later decision |
| Abstraction | Generation / CertificateClass / issuerRef |
| Raft | Single crypto profile for peers |
| Claims | No “PQ-ready” until backlog exit criteria |

### Explicitly deferred

| Topic | Why defer |
|-------|-----------|
| Exact ML-DSA parameter set | Ecosystem and OpenSSL/Go timing |
| Composite certificates vs dual certs | Standards still moving; dual-issue is enough |
| In-process hybrid TLS date | Depends on runtime support |
| PQ KEM wrap of master | Optional compliance path only |
| Forcing all tenants to g2 | Breaks legacy |

---

## 10. Open questions for later design review

1. Is `cryptoGeneration` on the Certificate CRD sufficient, or is CertificateClass mandatory for v1 of the abstraction?  
2. Should g1 mean “RSA-2048 only” or “any classical algorithm the platform chooses under g1”? (Recommendation: **platform-defined classical set**, documented per release.)  
3. Dual API ports vs mesh-only hybrid for PQ-2?  
4. How does ACME / public trust interact with generations (likely g1-only forever for public CAs)?  
5. Operator multi-issuer (Vault/ACME/SelfSigned) vs crypto generation — orthogonal axes; both may appear on one Certificate.

---

## 11. Document map (this discussion → artifacts)

| Discussion theme | Captured in |
|------------------|-------------|
| Are we PQ-ready? | [current-state.md](current-state.md) |
| How to improve each layer | [roadmap.md](roadmap.md) |
| Dual-stack mechanics | [dual-crypto-planes.md](dual-crypto-planes.md) |
| g1/g2/g3 and Harbor | [crypto-generations.md](crypto-generations.md) |
| Work items | [backlog.md](backlog.md) |
| This narrative | **This file** |

---

## 12. Summary

The architecture discussion concluded that KNXVault should become **PQ-aware and dual-stack capable** without forcing PQ onto Harbor or legacy Kubernetes clients. The preferred abstraction is **crypto generations (g1 default classical, g2+ opt-in)** mapped to **profiles and issuers**, with **shared AES envelopes** and **split certificate/TLS planes**. Harbor remains a Secret consumer pinned to **g1** by the platform; it never “calls” a generation. Implementation is phased in the [PQ backlog](backlog.md); the product is **not** post-quantum ready until those gates say so.
