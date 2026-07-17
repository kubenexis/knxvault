<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# PQ readiness — roadmap and way forward

Suggested path from discussion (2026-07). Complements the standalone [PQ backlog](backlog.md).

## Priority order (risk)

| Priority | Surface | Why |
|----------|---------|-----|
| **P0** | **TLS (API + Raft)** | Harvest-now / decrypt-later on sessions and key exchange |
| **P1** | **PKI (CA + leaves)** | RSA signatures/keys break under Shor; long-lived roots hurt most |
| **P2** | **Envelope AES-256** | Already sound classical choice; agility + custody |
| **P3** | **Master/DEK wrap AES-256** | Same; lifecycle over algorithm fashion |

## Principles

1. **Do not break Harbor / legacy K8s** — default plane stays classical (**g1**).  
2. **Dual-stack, not flip-a-switch** — classical and PQ-capable apps coexist.  
3. **Generations as contracts** — apps bind to `g1`/`g2`/…; platform maps to algorithms.  
4. **AES stays for bulk secrets** — PQ KEMs wrap keys; AEAD encrypts data.  
5. **Agility before exotic algorithms** — versioned formats and algorithm fields first.  
6. **Honest claims** — “PQ-aware / migration-ready” before “PQ-ready.”

## Phases

| Phase | Name | Scope | Effort | Breaks Harbor if default? |
|-------|------|--------|--------|---------------------------|
| **PQ-0** | Document & harden | Threat model; AES stance; RSA-4096/ECDSA option; TLS1.3 everywhere; short leaf TTL; CA rollover practice | S | No |
| **PQ-1** | Agility | `cryptoGeneration` / algorithm fields; envelope alg version; CertificateClass / issuer `platform-g1` | M | No (default g1) |
| **PQ-2** | Transit hybrid | Edge proxy hybrid TLS **or** in-process hybrid when stable; dual listener optional | M | No if Harbor unchanged |
| **PQ-3** | Dual PKI planes | Second CA/issuer `platform-g2`; policy allow-list; dual-run docs | L | No if Harbor pinned g1 |
| **PQ-4** | PQ signatures | ML-DSA (e.g. OpenSSL provider) for allow-listed apps; client matrix | L | Yes if forced on Harbor |
| **PQ-5** | Optional PQ KEM wrap | Hybrid wrap of KEK only if policy requires | L | No |

Detailed dual-stack: [dual-crypto-planes.md](dual-crypto-planes.md).  
Generation model: [crypto-generations.md](crypto-generations.md).

## Layer-specific way forward

### 1. Secrets at rest (AES-256-GCM + random DEKs)

**Keep** current design (`internal/crypto/envelope.go`).

| Action | Type |
|--------|------|
| High-entropy master only (`openssl rand -base64 32`) | Ops |
| Document Grover/Shor stance in security model | Docs (PQ-0) |
| Formal envelope `alg` / version for future AEAD | Product (PQ-1) |
| Proven re-encrypt after master rotation | Ops / existing jobs |

**Do not** replace bulk AES with a KEM.

### 2. Master / DEK wrapping (AES-256-GCM)

| Action | Type |
|--------|------|
| Master ≠ unseal; sealed Secret / KMS; offline backup | Ops |
| KeyRing multi-version until re-encrypt done | Already present |
| Optional later hybrid KEK wrap | PQ-5 only if required |

### 3. PKI (RSA today)

| Stage | Action |
|-------|--------|
| **A Classical harden** | Prefer 4096 RSA or ECDSA P-384 for new roots; short leaf TTL; intermediate online, root colder |
| **B Agility** | Algorithm / generation on CA and issue APIs; stop hard-coding RSA-only in all paths |
| **C Dual then PQ** | `platform-g1` classical CA + later `platform-g2` PQ/hybrid; dual-issue only where needed |
| **D Migrate** | New intermediate → re-issue leaves → retire old CA |

Code: `x509native/issuer.go`, OpenSSL backend, operator CRDs.

### 4. TLS (API + Raft mTLS)

| Stage | Action |
|-------|--------|
| **A Harden** | TLS 1.3 only (already in-process); Raft mTLS on; restrict unseal network path |
| **B Hybrid transit** | **Edge proxy** (fastest) or in-process hybrid when Go/OpenSSL ready |
| **C Dual listener** | `:8200` classical, `:8201` hybrid (optional) |
| **D PQ certs on wire** | Only after PKI g2+ and client matrix green |

**Raft:** prefer one cluster-wide mTLS profile; do not run two Raft fabrics for crypto dual-stack.

## Compatibility with K8s / Harbor

| Change | Harbor / legacy K8s |
|--------|---------------------|
| AES envelope work | Unaffected (never sees DEKs) |
| g1 classical certs for `harbor-tls` | Compatible |
| Force g2/PQ cert into Harbor Secret | **Likely break** |
| Hybrid only on knxvault admin API | Harbor unaffected |
| Default generation remains g1 | Safe |

Harbor does **not** negotiate g1/g2. Platform pins Harbor’s `KNXVaultCertificate` to **g1** and chart `certSource: secret`. See [crypto-generations.md](crypto-generations.md#harbor-never-calls-generations).

## What not to do

- Claim PQ-ready after AES-only review  
- Global “enable PQ” flag for all Certificates  
- Pure PQ certs before clients understand them  
- Larger RSA (8192) as a substitute for PQ  
- Two independent Raft clusters solely for classical vs PQ  

## 90-day minimal program (PQ-0 + start PQ-1)

1. Publish this `docs/pq/` section and link from security model.  
2. Document at-rest AES-256 and non-PQ PKI/TLS honestly.  
3. Recommend RSA-4096 or ECDSA for new CAs; short leaf TTL.  
4. Design `cryptoGeneration` + `platform-g1` issuer naming.  
5. Practice CA rollover (needed for any future PQ migration).  
6. Optional: edge hybrid TLS in front of knxvault API only.

## Related

- [Current state](current-state.md)  
- [PQ backlog](backlog.md)  
- [Envelope encryption](../architecture/envelope-encryption.md)  
