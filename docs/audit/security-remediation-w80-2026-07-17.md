<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security remediation — W80 High/Medium pack (2026-07-17)

Follow-up to the post-W79 residual audit. Closes observed **High** and **Medium** findings that remain actionable without HSM/multi-tenant SaaS scope.

## High / Medium remediations

| ID | Severity | Finding | Remediation |
|----|----------|---------|-------------|
| W80-01 | Medium | Cloudflare DNS-01 used bare `http.Client` (env proxy / SSRF class) | Default client is `SafeHTTPClient` (`Proxy: nil` + dial-time IP checks) |
| W80-02 | Medium | Managed SQL allowed `GRANT ALL` / `IN ROLE` / `IN GROUP` / `SET ROLE` | Deny-list extended in `ValidateManagedSQLStatements` |
| W80-03 | Medium | Coarse `"pki"` write still authorized native PKI writes | Production forces `AllowCoarsePKIWrite=false`; fine-grained `pki/ca\|roles\|issue\|sign\|revoke` only. Lab keeps legacy fallback via `KNXVAULT_ALLOW_COARSE_PKI_WRITE` |
| W80-04 | Medium | Operator namespaced Secrets Role was full CRUD | Verbs reduced to `get`, `create`, `update`, `patch` (no list/watch/delete) |
| W80-05 | Medium | Production unseal CIDRs only blocked `/0` | Also reject IPv4 prefix &lt; `/8` and IPv6 &lt; `/32` |
| W80-06 | Medium | Exposure report anti-replay was process-local only | Optional shared `ExposureReplayStore` via Valkey/cache `Incr`; multi-node HA when `KNXVAULT_VALKEY_CACHE_URL` set |
| W80-07 | Medium | Lab security profile is process default (set-and-forget risk) | Doctor warns when profile is lab against non-loopback API; production kustomize + docs emphasize `KNXVAULT_SECURITY_PROFILE=production` |
| W80-08 | Medium | Base NetworkPolicy had ingress-only / unrestricted egress | Base NetPol adds default-deny egress with DNS + Raft + API allows (production NetPol remains stricter) |

## Documented residual (unchanged by design)

- Seal does not wipe master key from memory (API fence; HSM/KMS is M-CUSTODY-1).
- Soft multi-tenant (W64), cleartext Raft metadata (ADR-0005).
- Exposure HA replay requires shared Valkey (or sticky sessions) — process-local alone is insufficient across nodes.

## Verify

```bash
make quality
go test ./internal/acme/ ./internal/auth/ ./internal/config/ ./internal/domain/secrets/ \
  ./internal/api/middleware/ ./pkg/doctor/ -count=1
```
