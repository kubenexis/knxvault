<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Formal 10-Cycle Code Review — Entire KNXVault Codebase

| Field | Value |
|-------|-------|
| **Review ID** | `7f32c606` |
| **Date (UTC)** | 2026-07-16 |
| **HEAD** | `5242c30` |
| **Scope** | **Full codebase** (~75 Go packages, ~455 `.go` files, deployments, CSI/ESO/operator/webhook) |
| **Method** | 10 iterative structured cycles (golang-k8s checklist) + multi-pass `/review`-style subagent audits |
| **Companion multi-pass files** | [review-skill-full-codebase](review-skill-full-codebase-7f32c606.md), [security-deep-dive](review-skill-security-deep-dive-7f32c606.md) |
| **`go test ./...`** | **PASS** (all packages green at audit time) |

---

## Executive summary

KNXVault is a **mature, well-layered** secrets/PKI platform: envelope AES-256-GCM before Raft, sandboxed OpenSSL, path-aware RBAC, K8s/OIDC auth, CSI/ESO/operator/webhook surfaces, and a strong unit/integration test suite (`go test ./...` green).

**Overall risk for multi-tenant production: High.**  
**Overall risk for controlled private-CA POC: Medium (conditional ship).**

Dominant systemic themes:

1. **Operational controls incomplete** — seal does not block secret *reads*; seal/init/AppRole not HA-durable  
2. **K8s product surfaces** — webhook plaintext TLS; ESO unauthenticated fetch + SA fallback; operator cluster-wide Secrets; missing server TokenReview RBAC  
3. **ACME multi-issuer alpha** — SSRF webhooks, HTTP-01 not wired, TOS hard-coded (from prior multi-issuer review; still open)

**Composite posture:** ~**7.0–7.2 / 10** technical (aligns with prior BFSI formal audit of 2026-07-01, adjusted for new operator/ACME/ESO findings).

### Top 10 by business impact

| # | Severity | Finding |
|---|----------|---------|
| 1 | **Critical/bug** | ESO `/fetch` can run without caller auth (SA auto-login) |
| 2 | **Critical/bug** | Mutating webhook listens **plaintext HTTP** (`failurePolicy: Fail` blocks pods) |
| 3 | **High/bug** | Seal allows authenticated **GET** of secrets while “sealed” |
| 4 | **High/bug** | Seal state not durable / starts unsealed after restart |
| 5 | **High/bug** | AppRole in-memory only (not Raft) — HA/cert-manager AppRole broken |
| 6 | **High/bug** | Production StatefulSet SA **missing TokenReview** RBAC |
| 7 | **High/bug** | Operator ACME DNS webhook **SSRF** |
| 8 | **High/bug** | OpenSSL `-subj` **DN injection** via CommonName `/` |
| 9 | **High/bug** | Operator ClusterRole **cluster-wide Secrets CRUD** |
| 10 | **High/bug** | Init flag process-local — re-init / CA sprawl after restart |

---

## Cycle 1 — Architecture & design

| Finding | Sev | Evidence / notes |
|---------|-----|------------------|
| Clean layering: domain → engine → service → API | Pass | Consistent ports/adapters; engines seal before repo |
| Operator multi-issuer + vaultcompat façade | Pass (design) | Product profiles over services is correct direction |
| AppRole / init / seal not in Raft control plane | High | HA consistency gap for “production” auth methods |
| ACME HTTP-01 architecture incomplete | High | Env loaded; no shared solver + listener (prior audit) |
| EngineRegistry unused for dynamic dispatch | Low | Prior formal audit; still unused |

---

## Cycle 2 — Cryptography

| Finding | Sev | Evidence / notes |
|---------|-----|------------------|
| Encrypt-before-replicate for KV/CA keys/DB/SSH | Pass | `crypto.Seal` → `data_enc`/`dek_enc`; ADR-0004 |
| Cleartext metadata (paths, policies) intentional | Med | ADR-0005 — residual recon risk on PVC steal |
| DEK memzero underused on hot path | Med | `memzero` exists; Seal/Open should zero DEKs |
| No mlock for master key | Med | BFSI gap (prior audit) |
| OpenSSL subject DN injection via CN | High | `openssl_backend.go` `/CN=` + raw CN |
| OpenSSL sandbox solid (temp 0700, minimal env, breaker) | Pass | `wrapper.go` SafeExec |
| ACME `SkipTLSVerify` passthrough | High | Lab flag can hit production LE if mis-set |

---

## Cycle 3 — Authentication & authorization

| Finding | Sev | Evidence / notes |
|---------|-----|------------------|
| K8s login fail-closed with Raft without TokenReview | Pass | Design correct |
| **Missing TokenReview RBAC on server SA** | High | `deployments/k8s/role.yaml` leases only — production K8s auth broken/Forbidden |
| Path-aware KV RBAC + agent prefix | Pass | Real enforcement |
| AppRole not Raft-replicated | High | `approle.go` |
| Lockout process-local + IP key | High | Multi-node bypass; XFF spoof if proxies untrusted |
| SyncRBAC errors ignored (stale allow) | Med | `Authorize` `_ = SyncRBAC` |
| Root token 365d + admin `*` | Med | Long-lived superuser |
| Agent delegate TTL uncapped | Med | Large TTL blast radius |
| Auth middleware fail-open if svc nil | Med | Pattern risk |
| Login rate limit off in prod ConfigMap | High | `RATE_LIMIT_ENABLED: false` |

---

## Cycle 4 — Raft / storage / HA

| Finding | Sev | Evidence / notes |
|---------|-----|------------------|
| Dragonboat HA substrate production-viable | Pass | Prior audit score high |
| Raft mTLS optional; not in default ConfigMap | Med | Inter-node traffic may be cleartext in-cluster |
| Backup completeness gaps (NHI, some metadata) | Med | Prior audit |
| Seal/init not in Raft | High | Cycles 1–3 |

---

## Cycle 5 — API & middleware

| Finding | Sev | Evidence / notes |
|---------|-----|------------------|
| SealGuard GET allowed while sealed | High | Secret exfil during “incident seal” |
| Unauthenticated `/metrics` | Med | Recon signal |
| Unauthenticated `/sys/unseal` (rate limited) | Med | Network-expose carefully |
| HTTP server missing ReadHeaderTimeout etc. | High | Slowloris / exhaustion |
| Rate limiter map unbounded | Med | Memory growth under scan |
| OpenAPI drift vs router | Med | Prior audit |
| Vaultcompat mount-level coarse `pki` write | Med | Multi-tenant over-auth |

---

## Cycle 6 — Operator & multi-issuer ACME

| Finding | Sev | Evidence / notes |
|---------|-----|------------------|
| Vault-mode CRD path lab-proven | Pass | E2E 41/41 |
| SelfSigned path lab-proven | Pass | |
| ACME HTTP-01 non-functional | High | No listener; ephemeral MemoryHTTP01 |
| AcceptTOS hard-coded true | High | |
| DNS webhook SSRF | Critical/High | |
| ClusterIssuer secret namespace empty/wrong | High | |
| Gateway RBAC missing | High | |
| Cluster-wide Secrets CRUD | High | Default rbac.yaml |
| CertificateRequest ignores multi-issuer | High | Prior review |
| PrivateKeySecretRef unused | High | Account key churn |

---

## Cycle 7 — Kubernetes products (CSI / ESO / webhook)

| Finding | Sev | Evidence / notes |
|---------|-----|------------------|
| CSI TokenReview RBAC present | Pass | Unlike server SA |
| CSI socket dir 0755 | Med | Tighten perms |
| **ESO fetch unauthenticated + SA fallback** | Critical | Cluster secret store footgun |
| ESO plain HTTP ListenAndServe | Med | In-cluster plaintext secrets in responses |
| **Webhook plain HTTP on :9443** | Critical | Incompatible with K8s admission + Fail policy |
| NetworkPolicy incomplete for CSI/ESO/operator clients | Med | |

---

## Cycle 8 — Deploy / supply chain / config

| Finding | Sev | Evidence / notes |
|---------|-----|------------------|
| StatefulSet non-root, drop caps, RO rootfs, seccomp | Pass | Hardened defaults |
| Rate limit disabled in production ConfigMap | High | |
| Production security ValidateSecurity incomplete | Med | No force TLS/raft mTLS/rate limit |
| SPDX / no lego for ACME | Pass | x/crypto only |
| License check scripts present | Pass | |

---

## Cycle 9 — Testing & quality gates

| Finding | Sev | Evidence / notes |
|---------|-----|------------------|
| `go test ./...` green | Pass | Audit-time |
| Strong unit coverage on pure packages / engines | Pass | |
| No e2e: webhook TLS, ESO authz deny, sealed-read, AppRole HA | High gap | |
| ACME only mock unit tests | High gap | |
| Coverage gate excludes controllers (documented pattern) | Low | |

---

## Cycle 10 — Claim gates & residual product risk

| Claim | Status after full-codebase review |
|-------|-----------------------------------|
| Secrets platform with Raft + envelope crypto | **Met** (core) |
| Replace cert-manager for **Vault-issued** TLS | **Met** (operator vault path + lab) |
| Replace cert-manager for **ACME/public** TLS | **Not met** until ACME Critical/High fixed |
| Full multi-tenant BFSI production | **Not met** — seal, ESO, webhook, TokenReview RBAC, rate limit |
| Vault product profile cert-manager dual-run | **Partial** — AppRole HA gap |

---

## Consolidated severity rollup (unique themes)

From multi-pass subagent audits (36 full + 16 security, with overlap):

| Severity | Approx unique material themes |
|----------|-------------------------------|
| Critical / bug | Webhook HTTP, ESO unauth fetch, ACME SSRF |
| High / bug | Seal reads, seal durability, AppRole/init HA, TokenReview RBAC, OpenSSL DN, operator Secrets RBAC, ACME HTTP-01/TOS/secrets |
| Medium / suggestion | Rate limit off, Raft mTLS optional, metrics open, SyncRBAC fail-open, agent TTL, memzero, NetworkPolicy, OpenAPI drift |
| Low / nit | Client TLS ergonomics, fingerprint helper, docs overclaim |

**Multi-pass review-skill totals (raw):**

| Source | Bugs | Suggestions | Nits | Total |
|--------|------|-------------|------|-------|
| Full-codebase multi-pass | 11 | 23 | 2 | **36** |
| Security deep dive | 8 | 6 | 2 | **16** |
| Prior multi-issuer-only review | 10 | 3 | 1 | 14 |

---

## Recommended actions

### Immediate (before multi-tenant / ESO / webhook / ACME prod)

1. Webhook: TLS server + cert mount; never plain HTTP with Fail policy  
2. ESO: require caller token/mTLS; never auto-login SA for anonymous  
3. Seal: block secret reads when sealed; persist seal / start sealed when unseal key set  
4. Deployments: TokenReview ClusterRole for server SA; rate limit on by default  
5. AppRole: Raft persistence or disable under multi-node Raft  
6. ACME: SSRF allowlist, AcceptTOS field, shared HTTP-01, account key Secret, Gateway RBAC  
7. OpenSSL: reject `/` and control chars in CN  

### Short-term

- Init state in Raft  
- Production ValidateSecurity expansion (TLS, raft mTLS, rate limit)  
- Metrics/NetworkPolicy hardening  
- Pebble ACME e2e; sealed-read tests; ESO unauth negative tests  

### Platform

- Re-run this full-codebase audit each major milestone  
- Keep formal BFSI audit + this review as dual track (product vs compliance)

---

## Verdict

| Scope | Decision |
|-------|----------|
| Private CA + operator vault path + vaultcompat (controlled cluster) | **Conditional Go** |
| Multi-tenant BFSI / open network | **No-Go** until Immediate list closed |
| ACME public TLS without cert-manager | **No-Go** until ACME High list closed |
| Enable mutating webhook as shipped | **No-Go** (plaintext HTTP) |
| Enable ESO adapter as shipped | **No-Go** (unauthenticated fetch) |

**Formal 10 cycles: complete (1–10).**  
**Multi-pass audit: complete (full-codebase + security deep dive subagents).**
