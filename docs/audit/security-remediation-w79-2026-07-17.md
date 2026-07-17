<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security remediation — W79 residual pack (2026-07-17)

Follow-up to the post-W78 full audit. Closes highest-value residuals.

## High / Medium remediations

| ID | Finding | Remediation |
|----|---------|-------------|
| W79-01 | `SafeHTTPClient` honored `HTTP(S)_PROXY` (SSRF bypass class) | `Proxy: nil` on all SafeHTTP transports |
| W79-02 | Operator ClusterRole Secret **read** cluster-wide | Removed secrets get/list/watch from ClusterRole; namespaced Role only |
| W79-03 | Coarse native `/pki` write | `RequireAnyPermission` with `pki/ca`, `pki/roles`, `pki/issue`, `pki/sign`, `pki/revoke` first, fall back to `pki` |
| W79-04 | Managed SQL allowed SUPERUSER/CREATEDB/… | Deny list extended |
| W79-05 | OIDC audience optional; HTTP JWKS | Audience required; non-loopback JWKS must be `https` |
| W79-06 | SSRF missed CGNAT / docs ranges / metadata hosts | Expanded `isBlockedIP` + hostname blocklist |
| W79-07 | Production unseal CIDR `/0` | Reject world-open unseal allowlists |
| W79-08 | ACME Profile.Validate weaker than Issue | Same SSRF + loopback-only SkipTLS escape as Issue |
| W79-09 | AppRole legacy unsalted hash | Salted hash only (re-register pre-W78 AppRoles) |
| W79-10 | issue-client-cert EKU | Force `ForceKeyUsage=client` |

## Documented residual (unchanged by design)

- Seal does not wipe master key from memory (API fence).
- Soft multi-tenant (W64), HSM/KMS (W63), cleartext Raft metadata (ADR-0005).
- Exposure report HA replay store (future).

## Verify

```bash
make quality
go test ./internal/acme/ ./internal/auth/ ./internal/config/ ./internal/domain/secrets/ ./internal/api/middleware/ -count=1
```
