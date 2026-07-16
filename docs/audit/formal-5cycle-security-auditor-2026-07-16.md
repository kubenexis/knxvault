# Formal 5-cycle security audit — KNXVault

**Date:** 2026-07-16  
**Persona:** `knxvault-security-auditor` (PKI architect + Golang security)  
**Mode:** full → remediate → `make test-coverage` (≥80%) → docs  
**HEAD baseline:** post-W50 / prior 10-cycle bugfix  

## Executive summary

| | |
|--|--|
| **Overall residual risk** | **Medium** (no Critical left unfixed in this pass) |
| **Deploy** | **Ship with mitigations** — production still requires NetworkPolicy, Raft mTLS, short root TTL, no insecure lab flags |
| **Coverage gate** | `make test-coverage` ≥ **80%** (pure operator + acme) |

Top three business-impact issues **found and fixed** this audit:

1. **CSR sign bypassed PKI role domain policy** — cert-manager / Vault-compat path could mint leaves for any SAN when a role had `AllowedDomains`.  
2. **`RequireKVAccess` fail-open** when auth service nil — same class as prior W50-11 / pathauth fixes.  
3. **Broken client-cert fingerprint** (not real SHA-256) — unsafe if used for binding identities.

---

## Threat model snapshot

| Assets | Actors | Boundaries |
|--------|--------|------------|
| Master/unseal keys, CA keys, DEKs, root token, KV secrets, ACME account keys, audit chain, Raft data | External client, compromised SA, K8s admin, disk thief, malicious Issuer/webhook author | API TLS, Raft mTLS, operator→vault, CSI/ESO→vault, ACME CA/DNS/HTTP-01 |

---

## Cycle log

### Cycle 1 — AuthZ middleware + PKI issue/sign surface

| Finding | Sev | Status |
|---------|-----|--------|
| `RequireKVAccess` nil service → `c.Next()` | High | **Fixed** — fail closed |
| `SignCSR` no `AllowedDomains` / MaxTTL enforcement | High | **Fixed** — `validateCSRAgainstRole` |
| IssueCertificate did not check CN against role (only DNSNames) | Medium | **Fixed** |

### Cycle 2 — ACME directory SSRF + ESO path

| Finding | Sev | Status |
|---------|-----|--------|
| ACME directory URL not statically SSRF-checked | Medium | **Fixed** — `ValidateDirectoryURL` (static; private IP literals / metadata hosts) |
| Full DNS fail-closed on directory would break mock/lab hostnames | — | Split `ValidateOutboundURL` (webhook+DNS) vs `ValidateDirectoryURL` |
| ESO `/fetch` path accepted `../` | Medium | **Fixed** — relative path only |

### Cycle 3 — mTLS identity + agent path

| Finding | Sev | Status |
|---------|-----|--------|
| `ClientCertFingerprint` returned raw prefix of DER, not SHA-256 | High | **Fixed** — SHA-256 hex of `cert.Raw` |
| `MTLSForPaths` prefix match could false-positive on shared prefixes | Low | **Fixed** — exact or `prefix/` |
| Agent path prefix accepted `..` | Medium | **Fixed** — reject `..`, normalize |

### Cycle 4 — Audit redaction expansion

| Finding | Sev | Status |
|---------|-----|--------|
| Audit sanitize missed `client_token`, `jwt`, `secret_id`, `master_key`, PEMs | Medium | **Fixed** — expanded sensitive key set |

### Cycle 5 — Regression tests, coverage gate, documentation

- Unit tests: CSR domain policy, ESO traversal, directory URL static SSRF, KV fail-closed, cert fingerprint, audit keys  
- `make test-coverage` + `go test ./...`  
- This report + security-model / testing / backlog notes  

---

## Positive controls (do not regress)

- Seal starts sealed with unseal key; SealGuard exact `/sys/unseal`  
- Auth / RequirePermission / RequirePathCapability fail-closed  
- DEK memzero on Seal/Open/Reencrypt  
- ACME AcceptTOS + public LE blocks SkipTLSVerify  
- Metrics bearer length-safe compare  
- Managed SQL allow-list; CSI socket 0700/0660  
- Root token default 72h; multi-node Raft mTLS gate  

---

## Residual risks (accepted / backlog)

| Item | Severity | Notes |
|------|----------|--------|
| SignCSR IP SANs not constrained by AllowedDomains | Medium | Domain policy is DNS/CN; track if IP-heavy workloads |
| ACME directory hostname rebinding (DNS→private after static check) | Low–Med | Webhooks still DNS-resolve; directory dial still hits configured host |
| Multi-share unseal / Shamir | Info | Progressive backoff only |
| AppRole not fully Raft-replicated multi-node | Info | File persist under data dir |
| Operator controller coverage outside pure-logic gate | Info | Controllers ~39% |

---

## Verification

```bash
make test
make test-coverage   # expect total ≥ 80% on gate packages
go test ./... -count=1
```

## Related docs

- Skill: `.grok/skills/knxvault-security-auditor/`  
- Prior audits: `docs/audit/formal-10cycle-bugfix-coverage-2026-07-16.md`, W50 backlog in `docs/backlog.md`  
