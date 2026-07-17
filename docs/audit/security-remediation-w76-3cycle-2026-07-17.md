<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Security remediation — W76 three-cycle review (2026-07-17)

Three consecutive review → fix → test → docs cycles against knxvault after W75 CIS hardening.

## Cycle 1 — Fail-closed unseal, seal-aware jobs, webhook SSRF

| ID | Severity | Finding | Remediation |
|----|----------|---------|-------------|
| W76-01 | High | Invalid `UnsealAllowCIDRs` logged and allowlist disabled (fail-open) | `ValidateSecurity` rejects bad CIDRs; router uses deny-ish nets if parse fails at runtime |
| W76-02 | High | Leader `JobRunner` ran crypto jobs while sealed | `JobRunner.SetSeal` + skip cleanup/renew/rotate/reencrypt when `Sealed()` |
| W76-03 | High | `notify.Webhook` had no SSRF controls | `ValidateURL` + `acme.SafeHTTPClient`; deps fail startup on bad exposure/rotation webhook URLs |

## Cycle 2 — Tenant lease isolation + path-safe lease IDs

| ID | Severity | Finding | Remediation |
|----|----------|---------|-------------|
| W76-04 | High | DB/SSH renew/revoke skipped tenant lease checks | `assertTenantLeaseAccess` on `DatabaseService`/`SSHService` Renew/Revoke |
| W76-05 | High | Lease IDs used `tenant/` slash, breaking Gin `:lease_id` | `tenant.ScopeLeaseID` uses `tenant.leaseid` (dot); legacy slash accepted for validation |
| W76-06 | Medium | Empty namespace soft-failed open on lease sys paths | Fail closed when tenant mode requires ns for lease access |

## Cycle 3 — Cert login privilege + coverage/docs

| ID | Severity | Finding | Remediation |
|----|----------|---------|-------------|
| W76-07 | Medium | Cert CN alone could synthesize privileged policy names | Block synthetic fallback for admin/root/… without explicit role |
| W76-08 | Docs | Multi-tenant lease ID format undocumented | Update `docs/operations/multi-tenant.md`, lease management |

## Coverage

- Operator pure-logic gate remains ≥80% (unchanged packages).
- New unit tests: unseal CIDR validation, sealed job guard, webhook SSRF, tenant lease assert, lease ID encoding.
- Best-effort: no new zero-value padding tests for thin `main` packages.

## Residual / deferred

- Master key rotation still process-local (W63-02); multi-node coordination not code-enforced.
- Shared lockout INCR race (document residual).
- ACME directory dial-time SSRF residual (webhooks already dial-safe).
- Exposure auto-revoke blast radius (HMAC key custody).

## Verify

```bash
make quality
make test-integration
```
