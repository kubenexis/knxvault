# BFSI prospect evaluation response (W43-08)

| Criterion | Status | Backlog | POC waiver |
|-----------|--------|---------|------------|
| Path-aware ACLs | **Met** | W41-01 | — |
| Deny precedence | **Met** | W41-03 | — |
| Policy simulation | **Met** | W41-04 | — |
| Auth login audit | **Met** | W43-01/02 | — |
| Login throttling / lockout | **Met** | W43-03/04 | — |
| OIDC role API | **Met** | W43-06 | — |
| Tenant repo isolation | **Partial** | W32-03 | Policy-only for POC |
| HCL import | **Met** | W41-08 | Subset only |
| Shamir unseal | **Gap** | LT-* | Single-key unseal documented |

## Go / No-Go

- **POC:** **GO** with documented waivers above.
- **Production BFSI:** **NO-GO** until tenant repo isolation (W32-03) and performance baselines (LT-12) close.

See [`docs/audit/formal-code-audit-2026.md`](../audit/formal-code-audit-2026.md) and [`docs/product/bfsi-poc-traceability.md`](bfsi-poc-traceability.md).