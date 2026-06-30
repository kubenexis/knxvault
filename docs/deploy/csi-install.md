# CSI provider installation (production)

KNXVault delivers secrets to workloads through the [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/). This guide covers production install of the upstream driver and the `knxvault-csi` provider.

## Prerequisites

- Kubernetes 1.25+
- KNXVault server reachable from worker nodes (ClusterIP or Ingress)
- KNXVault roles with `bound_service_account_names` / `bound_service_account_namespaces` for workload SAs
- Production auth uses **TokenReview** (automatic when the server runs in-cluster)

## 1. Install Secrets Store CSI Driver

```bash
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system \
  --set syncSecret.enabled=true \
  --set enableSecretRotation=true
```

`syncSecret` enables `secretObjects` sync (W39-06). `enableSecretRotation` allows version polling (W39-05).

## 2. Deploy KNXVault CSI provider

```bash
kubectl apply -f deployments/csi/rbac.yaml
kubectl apply -f deployments/csi/k8s-provider.yaml
```

The provider listens on `/var/run/secrets-store-csi-providers/knxvault.sock`.

## 3. Create SecretProviderClass and pod

```bash
kubectl apply -f deployments/csi/secretproviderclass-example.yaml
kubectl apply -f deployments/csi/pod-example.yaml
```

Adjust `vaultAddr`, `role`, and `objects` for your environment. See [Secrets injection](secrets-injection.md) for the parameter schema.

## 4. Optional mutating webhook

For annotation-based injection (`knxvault.io/inject=true`), label namespaces with `knxvault.io/webhook=enabled` and apply:

```bash
kubectl apply -f deployments/k8s/webhook/deployment.yaml
kubectl apply -f deployments/k8s/webhook/mutating-webhook.yaml
```

## Verification

```bash
kubectl logs -n knxvault -l app.kubernetes.io/name=knxvault-csi-provider
kubectl exec knxvault-csi-demo -- cat /mnt/secrets/db.env
```

## Local CI script

`scripts/test-csi-kind.sh` provisions a kind cluster and runs a smoke test (requires Docker + kind).

## Related

- [Kubernetes deployment](kubernetes.md)
- [Configuration reference](../installation/configuration.md)