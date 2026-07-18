<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: External Secrets Operator sync

Sync KNXVault KV secrets into native Kubernetes `Secret` objects for `envFrom` and legacy charts.

## When to use

- Helm charts require `existingSecret`
- Operators only read Kubernetes `Secret`
- GitOps workflows reference native Secrets

Prefer [CSI driver](csi-driver-integration.md) when file mounts suffice.

## Prerequisites

- External Secrets Operator installed
- TLS Secret `knxvault-eso-tls` (`tls.crt` / `tls.key`) for the adapter (W86-04)
- Scoped vault token in Secret `knxvault-eso-caller` key `token` (W86-05 — **not** root)
- KV secret exists
- Prefer **platform-edge** topology: [platform-edge-day0-day1.md](../operations/platform-edge-day0-day1.md)

## Step 1 — Seed KV

```bash
knxvault-cli kv put app/db password=eso-secret username=appuser
```

## Step 2 — Deploy knxvault-eso adapter (TLS + caller auth)

```bash
# TLS for adapter listen (:8443 HTTPS)
kubectl -n knxvault create secret tls knxvault-eso-tls --cert=eso.crt --key=eso.key
# Scoped token for ClusterSecretStore Authorization header
kubectl -n knxvault create secret generic knxvault-eso-caller --from-literal=token="$SCOPED_TOKEN"

kubectl apply -f deployments/external-secrets/knxvault-eso-deployment.yaml
kubectl apply -f deployments/external-secrets/clustersecretstore-webhook.yaml
```

**Security (W86-04/05):**

- Adapter requires TLS cert/key env (or lab-only `KNXVAULT_ESO_ALLOW_PLAINTEXT=true`).
- Unauthenticated `POST /fetch` returns **401**.
- `KNXVAULT_TOKEN_FILE` alone does **not** authenticate unless `KNXVAULT_ESO_ALLOW_TOKEN_FILE_PROXY=true` (break-glass).
- ClusterSecretStore URL is `https://knxvault-eso…:8443/fetch` with Bearer from `knxvault-eso-caller`.

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