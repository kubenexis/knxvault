<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security remediation — W78 full audit pack (2026-07-17)

Remediation of findings from the full security audit (post-W77). Report-only audit → this change set.

## High

| ID | Finding | Remediation |
|----|---------|-------------|
| W78-01 | CSR Email/URI SANs bypassed domain-restricted roles | `validateCSRAgainstRole` rejects email/URI unless `allowed_domains: ["*"]` |
| W78-02 | LDAP tokens renewable with empty `MaxExpiresAt` | LDAP login sets max lifetime = issue TTL |
| W78-03 | ACME `SkipTLSVerify` skipped directory SSRF | Always validate directory URL; skipTLS only allows loopback + dial-time filter |
| W78-04 | Auto PKI role used unconstrained `*` | Default role uses `_unconfigured.invalid` until admin sets domains; CreateRoot accepts optional `allowed_domains`; `PUT /pki/roles/:name` + CLI `--allowed-domains` |
| W78-05 | `sql_strict=false` + weak username | Reject `sql_strict=false`; safe-username check for managed DB |
| W78-06 | Operator ClusterRole Secrets CRUD cluster-wide | ClusterRole secrets = get/list/watch only; namespaced Role for write in `knxvault` (+ example) |
| W78-07 | Unauthenticated unseal with empty CIDRs | Production requires `KNXVAULT_UNSEAL_ALLOW_CIDRS` / `unseal_allow_cidrs` |

## Medium / Low

| ID | Finding | Remediation |
|----|---------|-------------|
| W78-08 | OIDC issuer optional; JWKS SSRF | Issuer required; JWKS URL SSRF-gated (loopback lab allowed) |
| W78-09 | Audit forward plain HTTP client | `SafeHTTPClient` + production URL validation |
| W78-10 | PKI KeyUsage not applied | Issue/SignCSR map server/client/code_signing EKU |
| W78-11 | CSI fileName path traversal | Basename-only validation |
| W78-12 | ImportCA key/cert mismatch | `verifyCertKeyMatch` before seal |
| W78-13 | CRL number fixed at 1 | Monotonic unix-nanos CRL number |
| W78-14 | AppRole unsalted hash / short secret | Role-salted SHA-256 + min 16-char secret_id (legacy hash still accepted) |
| W78-15 | Unseal length oracle | SHA-256 digest constant-time compare |
| W78-16 | SSH default port-forwarding | Default extensions: `permit-pty` only |

## Documented residual

- Operational **seal does not wipe master key** from memory (API/job fence only) — see `Seal()` comment and security model.
- Multi-tenant hard isolation (W64), HSM/KMS custody (W63), cleartext Raft metadata (ADR-0005).
- Coarse native `/pki` write ACL (path-scoped vault-compat sign remains finer).

## Verify

```bash
make quality
go test ./internal/engine/pki/ ./internal/auth/ ./internal/acme/ ./internal/config/ ./internal/inject/csi/ -count=1
```
