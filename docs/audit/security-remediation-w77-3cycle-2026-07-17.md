<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security remediation — W77 three-cycle audit (2026-07-17)

Full security audit after W76. Three remediation cycles focused on Critical/High findings.

## Cycle A — Critical identity & data integrity

| ID | Severity | Finding | Remediation |
|----|----------|---------|-------------|
| W77-01 | Critical | Cert login used built-in `PoliciesForRole` (CN=`admin` → full admin) | Fail-closed: only `GetStoredRole` / explicit role repository mappings |
| W77-02 | Critical | KV soft-delete wrote tombstone at latest+1; `GetLatest` still returned prior live data | `Delete` marks **current** latest via `DestroyVersion` |
| W77-03 | High | Tokens from `Issue`/`CreateToken` had empty `MaxExpiresAt` → infinite renew | Set max lifetime = issue TTL on Issue and CreateToken |

## Cycle B — Seal boundary & path safety

| ID | Severity | Finding | Remediation |
|----|----------|---------|-------------|
| W77-04 | High | OCSP unauthenticated decrypt while sealed | `SealGuard` on `POST /pki/ocsp/:id` |
| W77-05 | High | Login routes minted tokens while sealed | `SealGuard` on `/auth/*` and `/v1/auth/*/login` |
| W77-06 | High | `IssueListenerTLS` arbitrary filesystem write | Path jail under `/var/lib/knxvault/tls` (no `..`, must be under root) |
| W77-07 | Medium | Exposure auto-actions while sealed | Skip auto-revoke/rotate when sealed |

## Cycle C — Policy semantics + residuals + docs

| ID | Severity | Finding | Remediation |
|----|----------|---------|-------------|
| W77-08 | Medium | Glob `*` matched across `/` (over-broad vs Vault) | Single `*` is one path segment; `**` multi-segment |
| W77-09 | Docs | Operator guidance for cert roles, soft-delete, token max | This report + configuration notes |
| W76 residual pack | — | Prior uncommitted residuals (Incr lockout, ACME dial SSRF, exposure prefixes, master-key multi-node, Shamir) | Included in same change set |

## Coverage

- `make quality` gates: operator pure-logic ≥80%, acme ≥70%.
- New/updated unit tests: cert deny unmapped admin CN, KV delete hides get, glob segment rules, token max renew clamp, exposure path helpers, master-key multi-node block, memory Incr.

## Residual / deferred

- Full crypto key wipe on seal (master key remains in memory; seal is API/job fence).
- Admin revoke-by-id API and AppRole secret_id TTL (product backlog).
- Durable multi-node master keyring distribution beyond `MASTER_KEY_PREVIOUS` env.

## Verify

```bash
make quality
make test-integration
```
