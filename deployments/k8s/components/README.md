# Copyright Kubenexis Systems Private Limited.
# SPDX-License-Identifier: Apache-2.0

# Kustomize components (M-DTP-1)

Optional add-ons composed on top of `deployments/k8s/base` or `production`.

| Component | Path | Purpose |
|-----------|------|---------|
| `operator` | `components/operator` | Private PKI CRDs + controller |
| `csi` | `components/csi` | Secrets Store CSI provider |
| `webhook` | `components/webhook` | Mutating webhook CSI injection |
| `eso` | `components/eso` | External Secrets adapter |
| `acme-egress` | `components/acme-egress` | NetPol HTTPS egress for LE/ACME |

```bash
# Base only
kubectl apply -k deployments/k8s/base

# Production base (no ACME)
kubectl apply -k deployments/k8s/production

# Airgap core
kubectl apply -k deployments/k8s/overlays/airgap-core

# Platform edge (+ CSI/webhook/ESO)
kubectl apply -k deployments/k8s/overlays/platform-edge
```
