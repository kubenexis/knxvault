<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security audit remediation — W52 (2026-07-16)

Implements fixes for findings from the complete security audit (report-only pass that identified Critical/High/Medium issues and edge cases).

## Fixed in code

| ID | Severity | Fix |
|----|----------|-----|
| **W52-01** | Critical | `seal.state` never auto-unseals; only cryptographic `Unseal(key)` clears sealed state |
| **W52-02** | High | PKI roles require `allowed_domains` (use `"*"` explicitly); empty list default-deny |
| **W52-03** | High | CSR/issue require persisted PKI role when role repo configured; CreateRoot/Intermediate install default `"*"` role named after CA |
| **W52-04** | High | Vault-compat sign path no longer accepts coarse `pki` write alone; needs path patterns e.g. `pki/sign/*` or `pki/*` |
| **W52-05** | High | `RateLimitEnabled` defaults **true** |
| **W52-06** | High | CSI + SDK reject non-loopback `http://` vault URLs when HTTPS required |
| **W51-05** | Medium | IP SANs rejected unless role has `allowed_domains: ["*"]` |
| — | Medium | Default leaf TTL **72h** (was 720h) |
| — | Medium | Agent delegate requires explicit policy subset (no full parent inherit) |
| — | Medium | OCSP endpoint rate-limited (120 rpm) |
| — | Medium | `k8s_auth_insecure` requires lab `RAFT_ALLOW_INSECURE` |
| — | Low | Sidecar example no longer uses root token |

## Intentional residuals (not fully implemented)

| Item | Reason |
|------|--------|
| Multi-tenant isolation for DB/SSH/PKI/CSI | Large program (W32-*) |
| Cluster-wide lockout/rate-limit state | Needs shared store (Valkey) |
| Multi-share Shamir unseal | Feature project |
| AppRole Raft replication | Feature project |
| PKCS#11 HSM | W31-02 |
| Client-cert API login | W34-02 |
| OpenAPI behind auth | Operational tradeoff for tooling |

## Verify

```bash
make test
make test-coverage
go test ./... -count=1
```

## Operator notes

- After upgrade, policies that only grant `pki` + `write` must add `pki/*` or `pki/sign/*` for Vault-compat sign.
- New PKI roles must set `allowed_domains` (or `["*"]`).
- Vault restarts always require unseal when `KNXVAULT_UNSEAL_KEY` is set, regardless of `seal.state` contents.
