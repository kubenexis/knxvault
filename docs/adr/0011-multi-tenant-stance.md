# ADR-0011: Multi-tenant stance (soft vs hard isolation)

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-07-17 |
| **Backlog** | **W64-00** |

## Context

CIS-style multi-tenant SaaS isolation requires separate trust domains (keys, Raft, processes). knxvault also supports soft tenant mode for many Kubernetes namespaces in **one** platform org.

## Decision

1. **Default product claim: single trust domain** — one knxvault cluster per security classification / platform.  
2. **Soft multi-tenant** (`KNXVAULT_TENANT_MODE=true`) is **optional** for same-org namespace isolation (path prefixes, lease ID prefixes W64-01, SA namespace binding). It is **not** marketed as multi-customer SaaS isolation.  
3. **Hard multi-tenant** = deploy **separate knxvault instances** (separate master keys and Raft) per customer/tenant.

## Consequences

- Soft mode continues to improve (lease IDs, quotas) without claiming crypto isolation.  
- Metadata paths remain cleartext in Raft (ADR-0005) — reinforces single trust domain.  
- Runbook: [multi-tenant.md](../operations/multi-tenant.md)
