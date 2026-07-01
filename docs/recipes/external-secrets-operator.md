# Recipe: External Secrets Operator sync

Sync KNXVault KV secrets into native Kubernetes `Secret` objects for `envFrom` and legacy charts.

## When to use

- Helm charts require `existingSecret`
- Operators only read Kubernetes `Secret`
- GitOps workflows reference native Secrets

Prefer [CSI driver](csi-driver-integration.md) when file mounts suffice.

## Prerequisites

- External Secrets Operator installed
- `knxvault-eso` webhook adapter deployed
- KV secret exists

## Step 1 — Seed KV

```bash
knxvault-cli kv put app/db password=eso-secret username=appuser
```

## Step 2 — Deploy knxvault-eso adapter

```bash
make build-eso
kubectl apply -f deployments/external-secrets/knxvault-eso-deployment.yaml
kubectl apply -f deployments/external-secrets/clustersecretstore-webhook.yaml
```

## Step 3 — Install ESO (if needed)

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  -n external-secrets --create-namespace
```

## Step 4 — Create ExternalSecret

```bash
kubectl apply -f deployments/external-secrets/externalsecret-example.yaml
kubectl wait --for=condition=ready externalsecret/app-db -n default --timeout=180s
```

## Step 5 — Verify native Secret

```bash
kubectl get secret app-db-credentials -o jsonpath='{.data.password}' | base64 -d; echo
```

## Step 6 — Rotation

```bash
knxvault-cli kv put app/db password=eso-rotated username=appuser
# Wait refreshInterval (default 1h in example — lower for testing)
kubectl get secret app-db-credentials -o jsonpath='{.data.password}' | base64 -d; echo
```

## Security note

Native Secrets duplicate material in etcd. Restrict RBAC on the target namespace.

## Related recipes

- [CSI driver integration](csi-driver-integration.md)
- [Kubernetes ServiceAccount auth](kubernetes-serviceaccount-auth.md)

## See also

- [Kubernetes-native integrations](../integration/kubernetes-native.md)