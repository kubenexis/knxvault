<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security remediation W74 (2026-07-17)

Closes findings from the full-codebase security audit (comment-only report, same date).

| ID | Finding | Fix |
|----|---------|-----|
| **W74-01** | LDAP client headers configure directory | Server-side `LDAPDefaults` only; `/auth/ldap` unavailable when unset |
| **W74-02** | Loose LDAP bind success scan | Structural BindResponse parse (`0x61` + resultCode) |
| **W74-03** | LDAP DN injection via username | Allowlist `ValidateLDAPUsername` |
| **W74-04** | Wrap meta in-memory only | Sealed meta at `sys/wrapping/meta/*` + GC |
| **W74-05** | Identity in-memory only | Sealed snapshot `sys/internal/identity` |
| **W74-06** | Lease cascade / bulk empty filter | TokenID on DB/SSH issue; bulk requires selector |
| **W74-07** | Unwrap capability coarse | Unwrap requires `sys/wrapping` **read** (not write) |
| **W74-08** | Transit “sign” is HMAC | Documented; HMAC binds key name |
| **W74-09** | Transit no key binding | Plaintext prefix bind `knxtransit\|name\|ver\|` |
| **W74-10** | Cubby wipe versions | Destroy all listed versions |
| **W74-11** | Identity arbitrary policies | `SetPolicyExists` validates names when PolicyRepo set |
| **W74-12** | Transit map race under RLock | `getRecord` exclusive lock for cache fill |
| **SSRF** | Webhook DNS rebinding | `SafeHTTPClient` dial-time IP allowlist |
| **Prod** | LDAP insecure / plain ldap | Production profile rejects |

## Residual

- Soft multi-tenant lease ID prefix (W64-01) still open.  
- Valkey lockout still best-effort (not full Redis INCR atomicity).  
- Directory ACME URLs still use static SSRF (no resolve) for lab hostnames.  
- Software master key without KMS (W63).
