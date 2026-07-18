<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Airgap Day-0 checklist (base only)

**Milestone:** M-DTP-3 / W90-31  
**Role:** airgap-core / HA core instance

## 1. Images to transfer

| Artifact | Build / export | Required for airgap core |
|----------|----------------|--------------------------|
| `knxvault` server image | `make container-build` → `make container-export` | **Yes** |
| `knxvault-operator` image | `make k8s-operator-build` → export | Only if private CRD PKI |
| `knxvault-cli` host package | `make package-cli-release` / GitHub Release `knxvault-cli_*` archives / CI artifact | **Yes** (admin host; **separate** from container images) |
| CSI / ESO / webhook | same server image, different command | **No** for airgap core |
| Upstream CSI Driver / ESO | third-party | **No** for airgap core |

Offline matrix details: [build-and-deploy-images.md](build-and-deploy-images.md) § offline / airgap.

```bash
make container-export-all   # build/images/*-$(VERSION)-$(COMMIT).tar
make build-cli
# Copy tarballs + knxvault-cli to airgap media
```

## 2. Load images (airgap cluster)

```bash
# containerd / nerdctl example
nerdctl load -i knxvault-*.tar
nerdctl load -i knxvault-operator-*.tar   # optional
```

## 3. Secrets and Raft mTLS

1. Create custody Secret values (`MASTER_KEY`, `UNSEAL_KEY` distinct, `ROOT_TOKEN`, audit signing, metrics bearer).
2. Generate Raft peer mTLS materials into Secret `knxvault-raft-tls` (required for multi-node production).
3. Never grant the operator SA `get` on Secret `knxvault` (custody).

## 4. Apply base only

```bash
# Feature gates off, production profile, no CSI/ESO/webhook/ACME
kubectl apply -k deployments/k8s/overlays/airgap-core
```

Confirm rendered surface:

```bash
kubectl kustomize deployments/k8s/overlays/airgap-core | grep -Ei 'csi|eso|webhook|acme' && echo FAIL || echo OK
```

## 5. Feature gates (must be false on core)

- `KNXVAULT_AUTH_OIDC_ENABLED=false`
- `KNXVAULT_AUTH_LDAP_ENABLED=false`
- `KNXVAULT_AUDIT_FORWARD_ENABLED=false`
- `KNXVAULT_ACME_RELATED_ENABLED=false`
- Operator (if any): `KNXVAULT_OPERATOR_ACME_ENABLED=false`

## 6. Unseal and bootstrap

From an admin jump host (NetPol `knxvault.kubenexis.dev/unseal-client=true`):

```bash
export KNXVAULT_ADDR=https://knxvault.example:8200
export KNXVAULT_TOKEN=<bootstrap-root>
knxvault-cli doctor --profile production \
  --feature-oidc=false --feature-ldap=false \
  --feature-audit-forward=false --feature-acme=false
```

## 7. Explicit non-goals for airgap core

| Do not enable | Why |
|---------------|-----|
| Public OIDC / LDAP to internet IdP | Outbound identity plane |
| Let's Encrypt / public ACME | Public challenge plane |
| CSI / ESO / mutating webhook | Node and sync blast radius |
| Operator root token from custody Secret | W86-02 |

Optional private operator (vault-backed CRs only) may be added via `components/operator` with SA login and isolated Secrets RBAC — still **no** public ACME.
