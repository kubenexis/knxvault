<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Multi-tenant operations

## Product stance (W64-00 / ADR-0011)

| Mode | When | Isolation |
|------|------|-----------|
| **Single trust domain (default)** | One platform / org | Full cluster is one security domain |
| **Soft tenant mode** | Many K8s namespaces, same org | Path + lease ID prefixes; RBAC; **shared** master key |
| **Hard isolation** | Different customers / compliance | **Separate** knxvault deploy per tenant |

## Soft mode (`KNXVAULT_TENANT_MODE=true`)

- Secret paths scoped by tenant namespace (`tenant.ScopePath`).  
- SA tokens cannot spoof `X-KNX-Namespace`.  
- Dynamic **lease IDs** prefixed with `tenant/` (W64-01) for DB/SSH when namespace is present.  
- Cross-tenant lease access should use `tenant.ValidateLeaseIDAccess`.

## Hard isolation

```bash
# One namespace + one master/unseal key pair per customer
kubectl apply -k deployments/k8s/production -n customer-a
# Separate secrets — never share KNXVAULT_MASTER_KEY across customers
```

## Related

- [ADR-0011](../adr/0011-multi-tenant-stance.md)  
- [CIS hardening](../design/cis-hardening-improvements.md)  
