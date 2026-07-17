<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Secret sync decision matrix (M-SYNC-1)

How secrets leave knxvault into workloads and external stores.

## Pull into Kubernetes (preferred today)

| Mechanism | When to use | Install |
|-----------|-------------|---------|
| **Secrets Store CSI Driver** | Pod needs files/env at mount; least etcd leaf keys | [csi-install.md](../deploy/csi-install.md) |
| **External Secrets Operator** (`knxvault-eso`) | Native `Secret` objects for controllers/Ingress | [external-secrets recipe](../recipes/external-secrets-operator.md) |
| **Mutating webhook + CSI** | Annotation-driven inject | [mutating webhook recipe](../recipes/mutating-webhook-csi-injection.md) |
| **Response wrapping** | One-shot bootstrap to a human/CI (not long-lived sync) | [response-wrapping.md](../recipes/response-wrapping.md) |

## Push to external secret managers

| Target | Status |
|--------|--------|
| AWS Secrets Manager / Azure Key Vault / GCP SM | **Not near-term** — optional W73-02 controller later; or use cloud-native tools + knxvault as source of truth via CI unwrap |

## Decision flow

```text
Need secret in pod filesystem/env?
  → CSI (primary)

Need Kubernetes Secret object for another controller?
  → ESO webhook

One-time handoff (bootstrap token, initial password)?
  → Response wrapping

Multi-cloud push of many paths?
  → Defer; document pipeline with knxvault-cli + cloud CLIs
```

## Security notes

- Prefer short-lived tokens and path-scoped policies for CSI/ESO.  
- Avoid static root tokens in sync adapters.  
- Delivery `None` / CSI reduces private keys in etcd vs always writing TLS Secrets.
