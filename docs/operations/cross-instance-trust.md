<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Cross-instance trust pattern

**Milestone:** M-DTP-3 / W90-33  
**Related:** [instance-roles.md](instance-roles.md) · [ADR-0011 multi-tenant stance](../adr/0011-multi-tenant-stance.md)

## Pattern

```
┌─────────────────────┐         scoped token / K8s SA
│  Core instance      │◄────────────────────────────────┐
│  (airgap-core)      │                                  │
│  master/unseal,     │                                  │
│  private PKI, KV    │                                  │
└─────────────────────┘                                  │
                                                         │
┌─────────────────────┐         apps consume secrets     │
│  Platform edge      │──────────────────────────────────┘
│  CSI / ESO / webhook│  policies: secrets/kv/app/* only
│  optional OIDC      │  no sys/*, no pki/ca write
└─────────────────────┘
```

1. **Core** holds custody keys and issues short-lived credentials or serves KV/PKI under tight NetPol.
2. **Edge** authenticates to core with Kubernetes TokenReview or AppRole (never long-lived root).
3. Policies on core grant edge identity **least privilege** (path-scoped KV read, leaf issue only).

## Example edge role (core side)

```json
{
  "name": "platform-edge",
  "policies": ["edge-read"],
  "bound_service_account_names": ["knxvault-csi", "knxvault-eso"],
  "bound_service_account_namespaces": ["knxvault"]
}
```

Policy sketch:

- Allow `secrets/kv/apps/*` read  
- Deny `sys/*`, `pki/ca`, master/unseal paths  
- Optional: `pki/issue` for named intermediate only  

## Network

- Core NetPol: only namespaces labeled `knxvault.kubenexis.dev/api-client=true` (and admin unseal clients) reach `:8200`.
- Monitoring scrapes `:8201` metrics only (never unseal port).
- Edge instances may have broader egress for OIDC JWKS; core does not.

## What not to do

- Do not run multi-tenant SaaS isolation inside one process for hard isolation (ADR-0011) — use **instances**.
- Do not copy master/unseal keys to edge.
- Do not grant operator SA `get` on Secret `knxvault` in the core namespace (W86-01).
