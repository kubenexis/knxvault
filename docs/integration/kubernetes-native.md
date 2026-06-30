# Kubernetes-native integrations

KNXVault is designed as a **Kubernetes-native** secrets and PKI platform. These integrations are first-class product surfaces — not optional add-ons.

## Integration matrix

| Integration | Purpose | Status | Backlog / docs |
|-------------|---------|--------|----------------|
| **Secrets Store CSI provider** | Mount KV secrets as pod volumes (secret zero in env) | **Shipped** — `knxvault-csi` | [CSI install](../deploy/csi-install.md), Tier G (W39) |
| **External Secrets Operator** | Sync KNXVault secrets into native `Secret` objects when apps need `envFrom` / controllers | Planned — native provider | Tier H (W40-01) |
| **cert-manager Issuer** | Automate TLS certificates from KNXVault PKI | Planned — Vault API shim or native issuer | Tier H (W40-02) |
| **Kubernetes auth method** | `POST /auth/kubernetes` + TokenReview + SA role bindings | **Shipped** | [Integration overview](overview.md#kubernetes-serviceaccount-authentication) |
| **Mutating admission webhook** | Optional: inject CSI volumes from pod annotations | **Shipped** — `knxvault-webhook` | `deployments/k8s/webhook/` |
| **Multi-language SDKs** | Go, Python, Java, Rust, Node.js clients from OpenAPI | Go **shipped** (`pkg/client`); others planned | Tier H (W40-03–07) |

## When to use which path

```mermaid
flowchart TD
  subgraph mount [Volume mount — preferred]
    CSI[Secrets Store CSI Driver]
    CSI --> PodFiles[Secrets as files in pod]
  end
  subgraph sync [Native Secret sync]
    ESO[External Secrets Operator]
    CSISync[CSI secretObjects]
    ESO --> K8sSecret[Kubernetes Secret]
    CSISync --> K8sSecret
  end
  subgraph pki [TLS automation]
    CM[cert-manager Issuer]
    CM --> TLS[TLS Secret for Ingress/mTLS]
  end
  KV[KNXVault KV / PKI] --> CSI
  KV --> ESO
  KV --> CM
```

| Need | Use |
|------|-----|
| File-based secret delivery, minimal etcd exposure | **CSI provider** |
| `envFrom.secretRef`, legacy controllers, GitOps Secret refs | **External Secrets Operator** or CSI `secretObjects` |
| Ingress / workload TLS from vault PKI | **cert-manager** + KNXVault issuer |
| In-cluster API access | **Kubernetes auth** (SA JWT → scoped token) |
| Faster pod YAML (no hand-written SPC) | **Mutating webhook** (optional) |
| Application code outside cluster | **SDKs** or REST |

## Secrets Store CSI provider

Primary consumption path. Provider binary: `cmd/knxvault-csi`. Mount-time auth uses the pod ServiceAccount (TokenReview) — no static vault token in the provider DaemonSet.

```bash
make build-csi
kubectl apply -f deployments/csi/rbac.yaml -f deployments/csi/k8s-provider.yaml
```

See [CSI install runbook](../deploy/csi-install.md).

## External Secrets Operator

Use when workloads or platforms require a native Kubernetes `Secret` (e.g. Helm charts with `existingSecret`, operators that only read `Secret`).

**Near-term:** webhook-based `ClusterSecretStore` example in `deployments/external-secrets/` (calls KNXVault REST).

**Target:** native ESO provider (`provider: knxvault`) with Kubernetes auth, KV path mapping, and refresh intervals — **W40-01**.

## cert-manager Issuer

Use for automated certificate lifecycle (Ingress TLS, internal mTLS, workload certs).

**Target:** `ClusterIssuer` with `spec.knxvault` or **Vault-compatible PKI paths** so cert-manager's existing Vault issuer works against KNXVault — **W40-02**.

Example manifests (require W40-02 API shim): `deployments/cert-manager/`.

**Until W40-02 ships:** use the CronJob / operator patterns in [PKI Kubernetes integration](../operations/pki-kubernetes.md) to issue via `POST /pki/issue` and write `kubernetes.io/tls` Secrets.

## Kubernetes authentication method

Production path:

1. Server runs in-cluster (or with kubeconfig) → **TokenReview** validates SA JWTs.
2. Roles bind `bound_service_account_names` and `bound_service_account_namespaces`.
3. CSI / ESO / cert-manager controllers use their own SA to authenticate.

Dev-only: `KNXVAULT_JWT_SECRET` (HS256) or `KNXVAULT_K8S_AUTH_INSECURE=true` when Raft is off.

## Mutating admission webhook (optional)

Annotate pods to inject a CSI volume without writing `SecretProviderClass` references by hand:

```yaml
metadata:
  annotations:
    knxvault.io/inject: "true"
    knxvault.io/secret-provider-class: knxvault-app-db
    knxvault.io/inject-mount-path: /mnt/secrets
```

Deploy: `deployments/k8s/webhook/`. Namespace must be labeled `knxvault.io/webhook=enabled`.

## SDKs

| Language | Package / path | Status |
|----------|----------------|--------|
| Go | `pkg/client` | Shipped |
| Python | `clients/python/` | W40-04 — `make generate-clients` |
| Node.js (TypeScript) | `clients/typescript/` | W40-05 |
| Java | `clients/java/` | W40-06 |
| Rust | `clients/rust/` | W40-07 |

Generate from `api/openapi.yaml`:

```bash
make generate-clients   # requires Docker + openapi-generator
```

See [clients/README.md](../../clients/README.md).

## Related

- [Integration overview](overview.md)
- [Secrets injection](../deploy/secrets-injection.md)
- [Backlog Tier H](../backlog.md#tier-h--kubernetes-ecosystem-eso-cert-manager-sdks)