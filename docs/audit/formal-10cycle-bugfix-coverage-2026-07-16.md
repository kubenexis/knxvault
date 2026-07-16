# Formal 10-cycle technical review — bugfix, coverage, docs

**Date:** 2026-07-16  
**Repo:** knxvault (`main`)  
**Scope:** Full-codebase review with **identify → remediate → test → document** repeated **10 times**.  
**Coverage gate:** `make test-coverage` (`COVERAGE_MIN=80` on pure operator/acme packages).

## Baseline

| Metric | Before cycles | After cycles |
|--------|---------------|--------------|
| Operator pure-logic coverage (`coverage-operator.out`) | **74.0%** (gate fail) | **≥80%** (gate pass) |
| ACME package | ~70.5% | ~79%+ |
| reconcileutil | 71.4% / RequeueAfter 0% | **100%** |

---

## Cycle 1 — Coverage gate + ACME SSRF/account keys

**Review focus:** packages in `make test-coverage`; dead code paths at 0%.

| Finding | Severity | Remediation |
|---------|----------|-------------|
| `ValidateOutboundURL` / `PublicLEHost` untested (0%) | Medium (regressions) | Added `ssrf_test.go` |
| `PublicLEHost` used `strings.Contains` → false positives | Medium | Suffix / exact host match |
| Account key PEM paths under-tested | Low | RSA + PKCS8 round-trips |
| `RequeueAfter` untested | Low | Unit test |

**Docs:** this audit cycle log.

---

## Cycle 2 — HTTP client + metrics auth + pathauth fail-closed

| Finding | Severity | Remediation |
|---------|----------|-------------|
| `http.DefaultTransport.(*http.Transport)` type assert panic if replaced | High | Safe type assert + fallback transport |
| `subtle.ConstantTimeCompare` on metrics bearer **panics on length mismatch** | High | Compare SHA-256 digests of headers |
| `RequirePathCapability` **fail-open** when `svc == nil` | High (W50-11 regression class) | Fail closed like `Auth` / `RequirePermission` |
| DEK plaintext linger on `ReencryptDEK` | Medium | `memzero.Bytes` in `KeyRing.ReencryptDEK` |

**Tests:** `TestHandlerWithAuth`, pathauth nil-service test.

---

## Cycle 3 — Audit forwarder copy + lockout double-count

| Finding | Severity | Remediation |
|---------|----------|-------------|
| Audit forward queue held only shallow entry copy; `Details` map shared | Medium | Deep-copy `Details` map on enqueue |
| `noteLockoutFailure` incremented **both** IP and identity keys → dual-count / dual audit | Medium | Single primary lockout key (identity preferred) |

---

## Cycle 4 — Middleware auth headers + ACME LE skipTLS

| Finding | Severity | Remediation |
|---------|----------|-------------|
| `X-Vault-Token` extraction untested | Low | Unit test |
| `SkipTLSVerify` on public LE directory | High (policy) | Already blocked; added regression test |
| CSI socket perms | Medium | TestServeSocketPermissions |

---

## Cycle 5 — RBAC sync fail-closed

| Finding | Severity | Remediation |
|---------|----------|-------------|
| Fail-closed path untested | Medium | `TestAuthorizeFailClosedOnRBACSyncError` |

---

## Cycle 6 — ACME solver nil panics

| Finding | Severity | Remediation |
|---------|----------|-------------|
| `solve` called `http01`/`dns01.Present` without nil check → panic | High | Explicit “solver not configured” errors |

*(pickChallenge already skips missing solvers; solve is defense-in-depth.)*

---

## Cycle 7 — KV list prefix path traversal

| Finding | Severity | Remediation |
|---------|----------|-------------|
| `GET ?list=true&prefix=../../…` not sanitized | High | `cleanSecretPath` shared by path param and list prefix |

**Tests:** list-prefix rejection in `TestSecretsHandlerRejectsPathTraversal`.

---

## Cycle 8 — SealGuard path bypass

| Finding | Severity | Remediation |
|---------|----------|-------------|
| SealGuard allowed **any** path with suffix `/sys/unseal` (e.g. `/evil/sys/unseal`) | High | Exact path only after `path.Clean` |

**Tests:** `TestSealGuardRejectsSuffixBypass`.

---

## Cycle 9 — PKI sign path capability + residual review

| Finding | Severity | Remediation |
|---------|----------|-------------|
| Path-scoped PKI sign fallback unverified | Medium | `TestRequirePKISignCapabilityFallback` |
| OpenAPI structure | Low | Validated with YAML load |

No additional Critical defects in operator deepcopy / engine registry panic paths (init-time only).

---

## Cycle 10 — Full suite + gate + documentation

**Actions:**

1. `go test ./...` (unit + integration)
2. `make test-coverage` — enforce ≥80%
3. Update this formal report and security-model cross-links if needed
4. Commit remediation set

### Residual risks (accepted / follow-up)

| Item | Notes |
|------|--------|
| `realACME` method wrappers still 0% unit coverage | Exercised only against live ACME (Pebble/LE); mocks cover Issue path |
| Multi-share unseal | Progressive backoff (W50-28); **Shamir multi-share shipped in W53** — see [formal-w53](formal-w53-residual-features-2026-07-16.md), lab 53/53 |
| AppRole multi-node Raft replication | File persist; not fully Raft-replicated |
| Operator controller coverage ~39% | Outside pure-logic gate; expand when next operator milestone |

---

## Coverage gate definition (canonical)

```make
# Makefile test-coverage
# Packages: renew, secretutil, statusutil, reconcileutil, certlogic, acme
# Min: COVERAGE_MIN ?= 80
```

Operators should run `make test-coverage` in CI. Broader package totals (auth, middleware, app) remain best-effort improvements beyond the gate.

---

## Summary of remediations shipped this 10-cycle pass

1. SSRF / LE host matching hardened + tests  
2. Safe HTTP transport clone  
3. Metrics bearer compare without panic  
4. Path RBAC fail-closed  
5. DEK memzero on re-encrypt  
6. Audit forward details deep copy  
7. Lockout single primary key  
8. ACME solver nil safety  
9. KV list prefix sanitization  
10. SealGuard exact unseal path  
11. Coverage gate restored ≥80%  
12. Expanded unit tests across acme, middleware, auth, handlers, metrics, csi  

---

## How to re-run

```bash
make test
make test-coverage
go test ./... -count=1
```
