<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# PQ readiness — current cryptographic state

Assessment of KNXVault as implemented (2026-07). Implementation references: `internal/crypto/`, `internal/crypto/x509native/`, `internal/crypto/tlsconfig/`, [envelope encryption](../architecture/envelope-encryption.md).

## Verdict

**KNXVault is not post-quantum ready.** It uses classical cryptography end to end. Some layers age better under quantum assumptions than others.

## Layer table

| Layer | Today | Quantum picture |
|-------|--------|-----------------|
| **Secrets at rest (envelope)** | AES-256-GCM + random 32-byte DEKs | Symmetric; Grover roughly halves brute-force strength (256 → ~128-bit class). **Not** broken by Shor. Relatively good baseline if master key is high-entropy. |
| **Master / DEK wrapping** | AES-256-GCM with master key (KeyRing) | Same as envelope. No passphrase KDF (good — no weak password derivation). |
| **PKI (CA / leaves)** | RSA (default 2048+) SHA-256 via OpenSSL CLI and/or native Go | **Not PQ.** Shor breaks RSA (and ECDSA if used later without dual-stack). |
| **TLS (API)** | Server TLS; min TLS 1.3 in `tlsconfig` | Classical certs + classical groups as negotiated. **Not PQ.** |
| **TLS (Raft mTLS)** | Peer certs required multi-node (W50-20) | Same classical limitation. |
| **Unseal / Shamir** | Symmetric secret; GF(2^8) shares | Not public-key; threat is theft of material, not Shor on RSA. |
| **Tokens / audit HMAC** | Opaque tokens; optional HMAC signing | Symmetric/hash; not RSA. |

There is **no** ML-KEM, ML-DSA, SLH-DSA, hybrid TLS profile, or PQ certificate issuance in the product today.

## Code touchpoints

| Concern | Location |
|---------|----------|
| Envelope AES-GCM | `internal/crypto/envelope.go`, `service.go` |
| Native RSA issue | `internal/crypto/x509native/issuer.go` (`rsa.GenerateKey`, `SHA256WithRSA`) |
| OpenSSL RSA | `internal/crypto/pki/openssl_backend.go` (`genrsa`) |
| API TLS min version | `internal/crypto/tlsconfig/tlsconfig.go` (`MinVersion: tls.VersionTLS13`) |
| Raft mTLS requirement | `internal/config/security.go`, raft env |

## What “post-quantum ready” would require

1. **At rest** — AES-256 (present) + documented stance + format agility for future AEAD.  
2. **In transit** — TLS 1.3 **hybrid** KEMs (e.g. X25519+ML-KEM) on API and ideally Raft peers.  
3. **Identity / PKI** — issue and validate PQ or hybrid certificates when clients support them.  
4. **Migration** — dual CA / dual generation; re-issue leaves; dual-run trust.  
5. **Supply chain** — OpenSSL/Go versions and providers that implement chosen PQ algorithms.

Today: **(1) partial**; **(2)–(5) not started**.

## Practical takeaway

| Question | Answer |
|----------|--------|
| Harvest-now on **disk/Raft ciphertext** if AES keys stay secret? | Much better than RSA-at-rest; custody still critical. |
| CRQC against **RSA certs / classical TLS**? | Vulnerable in principle. |
| Claim “PQC-ready” for audits? | **No** without completing [backlog](backlog.md) gates. |

## Next

- [Roadmap & way forward](roadmap.md)  
- [Dual crypto planes](dual-crypto-planes.md)  
- [Crypto generations](crypto-generations.md)  
