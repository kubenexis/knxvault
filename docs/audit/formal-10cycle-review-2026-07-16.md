# Formal 10-Cycle Code Review — knxvault (`main` vs `origin/main`)

| Field | Value |
|-------|-------|
| **Review ID** | f29a75bd |
| **Scope** | merge-base `b973d53` → HEAD `ebc0af3` (15 commits) |
| **Date (UTC)** | 2026-07-16 |
| **Mode** | Formal iterative 10-cycle audit (golang-k8s checklist) + review-skill multi-pass |
| **Repo** | `/home/build01/repos/knxvault` |
| **Overall risk** | **High** (for production ACME/public TLS); **Medium** (vault-issued operator path already lab-proven) |

## Executive summary

The branch delivers a substantial cert-manager replacement surface: operator CRDs (W30+hardening), Vault product profile, multi-issuer ACME/SelfSigned, lab E2E 41/41, and strong pure-package unit coverage. **Vault-mode private CA automation is production-credible.** **ACME mode is not production-ready:** HTTP-01 is effectively non-functional (no shared challenge store / listener), ACME account keys are not persisted, ClusterIssuer secret resolution uses empty namespace, DNS webhooks allow SSRF, and `AcceptTOS` is hard-coded true. Safe to deploy **operator vault path + vaultcompat** with known gaps; **do not** enable ACME ClusterIssuers against Let's Encrypt until Critical/High items below are fixed.

**Top 3 by business impact**
1. ACME HTTP-01 broken end-to-end (ephemeral MemoryHTTP01 + `KNXVAULT_ACME_HTTP01_ADDR` never started)
2. ClusterIssuer ACME secrets / webhook security (empty ns; SSRF; unconditional TOS)
3. RBAC missing Gateway API rules while gateway shim can be enabled

---

## Cycle 1 — Architecture & design

| ID | Sev | Finding |
|----|-----|---------|
| C1-1 | High | **ACME architecture incomplete:** `issueACME` builds a **new** `MemoryHTTP01` per issue (`NewIssuerFromKind` → `BuildSolvers`). No process-wide challenge registry shared with an HTTP server. ACME CA cannot validate HTTP-01. |
| C1-2 | Medium | **`PrivateKeySecretRef` / account key path defined on CRD but unused** in `issueACME` — every order registers a new ACME account → LE rate limits. |
| C1-3 | Medium | **Product claim vs implementation:** docs claim ACME HTTP-01 “Supported”; lab E2E only proves SelfSigned + Vault. Marketing overshoots. |
| C1-4 | Low | Multi-issuer dispatch via `ResolvedIssuer` is clean; vault path remains behind service façade (good). |

**Evidence:** `internal/operator/controllers/issuer_backend.go:54-95`, `internal/operator/manager.go:38-56` (env loaded, never used), `internal/acme/issuer_factory.go`.

---

## Cycle 2 — Security & DevSecOps

| ID | Sev | Finding |
|----|-----|---------|
| C2-1 | **Critical** | **DNS-01 webhook SSRF:** `WebhookURL` is arbitrary; operator POSTs JSON from cluster network (`internal/acme/webhook.go:20-47`). No scheme/host allowlist, no block of link-local/metadata. Attacker with CRD write can probe internal services. |
| C2-2 | **High** | **`AcceptTOS: true` hard-coded** (`issuer_backend.go:61`) — legal/compliance risk; must require explicit `spec.acme.acceptTOS: true` on CR. |
| C2-3 | **High** | **`SkipTLSVerify` accepted for any directory** including production LE if mis-set (`issuer_backend.go:62`). Should refuse when Server contains `letsencrypt.org` / known public CA hosts. |
| C2-4 | **High** | **ClusterIssuer secret reads with `ns=""`** for cluster-scoped issuers (`issuer_backend.go:70`, `readSecretKey` at 97-114). Kubernetes secrets are namespaced — Cloudflare token lookup fails or is ambiguous. Need `secretNamespace` or default operator ns. |
| C2-5 | Medium | ClusterRole grants **cluster-wide secret CRUD** (`deployments/operator/rbac.yaml:26-28`) — over-broad for least privilege; prefer namespaced Role for TLS secrets + optional API-token secrets. |
| C2-6 | Medium | AppRole store is **in-memory only** (not Raft) — credentials lost on restart; multi-node inconsistent. |
| C2-7 | Low | Vaultcompat `X-Vault-Token` accepted (intended); ensure audit logs do not echo tokens (pre-existing pattern OK). |

---

## Cycle 3 — Reliability & error handling

| ID | Sev | Finding |
|----|-----|---------|
| C3-1 | **High** | HTTP-01 challenges never exposed: env `KNXVAULT_ACME_HTTP01_ADDR` loaded in `ConfigFromEnv` but **no `http.ListenAndServe` / manager.Add** wires `MemoryHTTP01.ServeHTTP`. |
| C3-2 | Medium | ACME challenge **CleanUp never called** after success/failure — DNS TXT records leak; HTTP tokens linger if shared store existed. |
| C3-3 | Medium | **Renew path only for Vault mode** (`certificate_controller.go` PreferRenew gated on Vault). ACME/SelfSigned re-issue only — OK for self-signed; ACME should re-order (acceptable) but docs should say so. |
| C3-4 | Medium | `ResolveVaultRole` **falls back to ref.Name on any Get error** (`resolve.go:23-27`) — typo CR name silently becomes vault role string; can cause confusing vault errors or wrong CA if name collides. Prefer NotFound-only fallback. |
| C3-5 | Low | Reconcile backoff present for vault errors; ACME network timeouts rely on 60s client — long blocking reconcile holds worker. |

---

## Cycle 4 — Scalability & performance

| ID | Sev | Finding |
|----|-----|---------|
| C4-1 | Medium | ACME `Issue` is **synchronous** in reconcile (RSA 2048 + multi-round ACME). Can exceed client-go timeout under load; prefer async Issuing status + requeue. |
| C4-2 | Low | Per-issue ECDSA account key gen + RSA leaf is CPU heavy; account reuse (C1-2) mitigates. |
| C4-3 | Low | Cloudflare zone list every Present without cache. |

---

## Cycle 5 — Testing & quality gates

| ID | Sev | Finding |
|----|-----|---------|
| C5-1 | **High** | **No integration test** that ACME HTTP-01 is reachable (only mock `ACMEAPI`). Gap hides C1-1/C3-1. |
| C5-2 | Medium | Lab E2E multi-issuer covers **SelfSigned only**, not ACME staging. |
| C5-3 | Medium | `cmcompat` coverage ~63%; conversion edge kinds thin. |
| C5-4 | Low | Coverage gate excludes controllers (~39%) — intentional pure-package gate; document so merge reviews do not assume controller coverage. |
| C5-5 | Pass | `internal/acme` unit tests ≥80%; vaultcompat + operator controller unit tests pass; lab E2E 41/41 for vault+selfsigned. |

---

## Cycle 6 — Kubernetes & platform

| ID | Sev | Finding |
|----|-----|---------|
| C6-1 | **High** | **RBAC lacks `gateway.networking.k8s.io` gateways** get/list/watch while `GatewayReconciler` can be enabled (`rbac.yaml` vs `gateway_controller.go`). Shim fails closed with Forbidden. |
| C6-2 | Medium | Issuer CRD schema dropped `required: [vaultCAName]` (good for multi-issuer) but **no OpenAPI oneOf** for vault|acme|selfSigned — invalid multi-mode specs rejected only at runtime. |
| C6-3 | Medium | Operator Deployment sample may not set ACME env / HTTP-01 Service — operational docs partial. |
| C6-4 | Low | Gateway controller soft-fails registration if GVK missing — good. |

---

## Cycle 7 — Operational readiness

| ID | Sev | Finding |
|----|-----|---------|
| C7-1 | Medium | No metrics for ACME vs vault issues (only generic IssuesTotal). Hard to SLO public TLS. |
| C7-2 | Medium | Support matrix / design docs exist; **runbook for ACME failure modes** (rate limit, pending authz) missing. |
| C7-3 | Low | Lab full E2E script and docs updated — good for private CA path. |

---

## Cycle 8 — API / vaultcompat profile

| ID | Sev | Finding |
|----|-----|---------|
| C8-1 | Medium | AppRole admin registration in-memory only (see C2-6). |
| C8-2 | Low | SignCSR role-as-CA-name fallback is intentional; document RBAC implication (any token with pki write can name any CA). |
| C8-3 | Pass | Health codes, sign body/response shape, X-Vault-Token middleware — aligned with cert-manager vault client. |

---

## Cycle 9 — Dependency & license

| ID | Sev | Finding |
|----|-----|---------|
| C9-1 | Pass | ACME uses existing `golang.org/x/crypto` (BSD) — no lego/MPL. |
| C9-2 | Low | No new direct deps in multi-issuer change — good. |

---

## Cycle 10 — Claim gate & residual risk

| ID | Sev | Finding |
|----|-----|---------|
| C10-1 | **High** | Claim “ACME HTTP-01 Supported” is **not met** until shared solver + listener + e2e against Pebble/staging. |
| C10-2 | Medium | Full cert-manager replacement for **all** K8s use cases still excludes Venafi/PCA and dual-serve `cert-manager.io` CRDs (documented) — OK if matrix is marketing source of truth. |
| C10-3 | Pass | Private CA + SelfSigned paths meet lab claim gate without cert-manager. |

---

## Consolidated findings (severity-ordered)

### Critical
1. **DNS webhook SSRF** — `internal/acme/webhook.go:20-47` — allowlist hosts/CIDRs; block private ranges.

### High
2. **HTTP-01 non-functional** — ephemeral MemoryHTTP01 + ACMEHTTP01Addr never started — `manager.go:56`, `issuer_backend.go:64-77`.
3. **AcceptTOS always true** — `issuer_backend.go:61`.
4. **ClusterIssuer secret namespace empty** — `issuer_backend.go:48-70`.
5. **SkipTLSVerify unrestricted** — `issuer_backend.go:62`.
6. **Gateway RBAC missing** — `deployments/operator/rbac.yaml`.
7. **No ACME HTTP-01 integration test** — tests only mock ACMEAPI.

### Medium
8. ACME account key not loaded from `PrivateKeySecretRef`.
9. Challenge CleanUp not invoked.
10. ResolveVaultRole silent name fallback on any Get error.
11. Synchronous ACME in reconcile.
12. Over-broad cluster secret RBAC.
13. Docs claim ACME HTTP-01 without e2e proof.
14. AppRole not Raft-replicated.
15. Missing ACME metrics / runbook.

### Low
16. Cloudflare zone list uncached.
17. Coverage gate excludes controllers (document).
18. CRD oneOf validation.

---

## Recommended actions

### Immediate (before ACME production)
- [ ] Shared `MemoryHTTP01` singleton + start HTTP server when `KNXVAULT_ACME_HTTP01_ADDR` set
- [ ] Persist ACME account key via `PrivateKeySecretRef`
- [ ] `acceptTOS` required field; refuse SkipTLSVerify for public LE hosts
- [ ] ClusterIssuer: `secretNamespace` or operator namespace for API tokens
- [ ] Webhook URL allowlist / private IP block
- [ ] Gateway RBAC rules
- [ ] Soften docs: ACME HTTP-01 “alpha / needs solver wiring” until e2e green

### Short-term
- [ ] Pebble-based ACME e2e in lab
- [ ] CleanUp challenges; async reconcile for ACME
- [ ] Tighten ResolveVaultRole NotFound-only fallback
- [ ] Namespaced secret RBAC examples

### Platform
- [ ] govulncheck/trivy on release; keep SPDX gate
- [ ] Formal claim gate checklist in CI (matrix test tags)

## Verdict

| Path | Ship? |
|------|-------|
| Operator **Vault** + vaultcompat | **Yes** (lab E2E proven); fix C3-4 when convenient |
| Operator **SelfSigned** | **Yes** for lab/dev |
| Operator **ACME** public TLS | **No** until Critical/High ACME items closed |

**Review cycles completed:** 10/10 formal.  
**Review-skill multi-pass:** companion file `grok-review-f29a75bd.md` (reviewer subagent / orchestrator consolidated).
