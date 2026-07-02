# Phase 4 — Ecosystem Design

Design outline for the next major phase of KNXVault. Phase 3 (Dragonboat Raft storage) is complete; Phase 4 focuses on ecosystem integration, hardware security, and operational maturity.

## Goals

| Goal | Success criteria |
|------|------------------|
| Kubernetes-native management | Operator reconciles CA and RBAC CRDs |
| Hardware security | HSM-backed CA key operations via OpenSSL engine |
| Multi-workload isolation | Namespace-scoped tenancy with policy boundaries |
| Performance at scale | Valkey read cache for hot paths (Apache 2.0) |
| Transport security | Full mTLS for API and client certificates |
| Disaster recovery | Automated DR failover and runbooks |

## Proposed wave breakdown

| ID | Title | Area | Effort | Depends on | Description |
|----|-------|------|--------|------------|-------------|
| **W30-01** | Kubernetes Operator scaffold | k8s | L | W29 | kubebuilder project, CRD types for `KNXVaultCA`, `KNXVaultPolicy` |
| **W30-02** | Operator reconciliation loop | k8s | L | W30-01 | Reconcile CRDs to KNXVault API; status conditions |
| **W31-01** | OpenSSL engine abstraction | crypto | M | W3-03 | Pluggable engine interface in `internal/crypto/openssl/` |
| **W31-02** | PKCS#11 HSM integration | crypto | L | W31-01 | Engine config via env; CA key generation on HSM |
| **W32-01** | Multi-tenancy policy model | auth | M | W13-01 | Namespace-scoped policy isolation and admin boundaries |
| **W32-02** | Tenant-aware API paths | api | M | W32-01 | Optional `X-KNX-Namespace` header enforcement |
| **W33-01** | Valkey read cache | storage | M | W26 | Cache public CA certs, CRLs, policy documents |
| **W33-02** | Cache invalidation on write | storage | S | W33-01 | Raft commit hooks invalidate cache entries |
| **W34-01** | Server mTLS | security | M | W5-03 | Require client certificates on secured routes |
| **W34-02** | Client cert issuance API | security | M | W34-01 | PKI role for API consumer certificates |
| **W35-01** | DR automation | ops | L | W27 | Cross-cluster backup replication and failover playbook |
| **W35-02** | Compliance audit packs | docs | M | W14 | Exportable audit bundles for SOC2/PCI evidence |

## Architecture (target state)

```mermaid
graph TB
    subgraph K8s
        Op[KNXVault Operator]
        CRD[CRDs: CA · Policy · Role]
    end

    subgraph KNXVault
        API[mTLS API]
        Cache[Valkey read cache]
        Raft[Dragonboat cluster]
        HSM[OpenSSL + PKCS#11 engine]
    end

    Op --> CRD
    Op --> API
    API --> Cache
    Cache --> Raft
    API --> HSM
```

## Non-goals (remain long-term future)

- Terraform provider
- Helm chart (may move earlier if Operator depends on it)
- Full Vault plugin system

## Dependencies and risks

| Risk | Mitigation |
|------|------------|
| HSM vendor lock-in | Abstract engine interface; test with SoftHSM |
| Valkey availability | Cache miss falls through to Raft; not required for correctness |
| Operator complexity | Start with CA + Policy CRDs only; expand incrementally |
| mTLS rollout | Opt-in flag before `KNXVAULT_MTLS_REQUIRED=true` default |

## Open questions

1. Should the Operator manage Raft cluster sizing or only application config?
2. Is Valkey a hard dependency or optional sidecar? (Optional — `KNXVAULT_VALKEY_CACHE_URL`; in-memory fallback per node.)
3. Which HSM vendors to certify first (YubiHSM, AWS CloudHSM, Thales)?

## Related documents

- [Backlog](../backlog.md) — authoritative work item tracking
- [HLD](../architecture/hld.md)
- [ADR index](../adr/README.md)