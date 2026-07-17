<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Instance roles (Distributed Trust Platform)

**Milestone:** M-DTP-3 / W90-30  
**Design:** [distributed-trust-platform.md](../design/distributed-trust-platform.md)

KNXVault is deployed as **instances** sized to use case. Critical material stays on a small **base** TCB; injection and public federation run on **edge** instances with scoped credentials.

## Roles

| Role | Overlay | Deploy surface | Purpose |
|------|---------|----------------|---------|
| **Airgap / HA core** | `deployments/k8s/overlays/airgap-core` | Base only (Core + K8s) | Master/unseal keys, critical secrets, private CA. No public OIDC, LE, CSI, ESO, webhook. |
| **Production base** | `deployments/k8s/production` | Base + production profile | Same surface as core; production security profile + metrics plane + Raft mTLS mounts. |
| **Platform / edge** | `deployments/k8s/overlays/platform-edge` | Base + CSI + webhook + ESO | App secret injection and sync. **Client** of core with scoped policies. |
| **Public TLS edge** | production + `components/operator` + `components/acme-egress` | Operator ACME enabled | Let's Encrypt / public ACME only where network policy allows. Do not co-locate with core custody when policy forbids it. |

## Feature gates (base fail-closed)

| Variable | Airgap / production base | Platform edge (example) |
|----------|--------------------------|-------------------------|
| `KNXVAULT_AUTH_OIDC_ENABLED` | `false` | `true` if federating |
| `KNXVAULT_AUTH_LDAP_ENABLED` | `false` | as needed |
| `KNXVAULT_AUDIT_FORWARD_ENABLED` | `false` | `true` only with SIEM URL |
| `KNXVAULT_ACME_RELATED_ENABLED` | `false` | `false` unless server-side ACME used |
| `KNXVAULT_OPERATOR_ACME_ENABLED` | `false` | `true` only on public TLS edge |

Doctor:

```bash
knxvault-cli doctor --profile production \
  --feature-oidc=false --feature-ldap=false \
  --feature-audit-forward=false --feature-acme=false
```

## Cross-instance trust

See [cross-instance-trust.md](cross-instance-trust.md) for edge-as-client patterns and scoped policies.

## Related

- [Airgap checklist](airgap-checklist.md)
- [Kubernetes deploy](../deploy/kubernetes.md)
- [Build and deploy images](build-and-deploy-images.md)
