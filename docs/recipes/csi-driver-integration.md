# Recipe: Secrets Store CSI driver integration

Mount KNXVault KV secrets as files in pods — no static vault tokens in workloads.

## What you will learn

- Installing the upstream CSI driver and `knxvault-csi` provider
- `SecretProviderClass` configuration
- Pod volume mounts and optional native Secret sync
- Rotation polling without pod restart

## Prerequisites

- Kubernetes 1.25+
- [3-node cluster](deploy-3-node-cluster.md) or single-node dev
- [Kubernetes ServiceAccount auth](kubernetes-serviceaccount-auth.md) configured (`app-sa` role)
- KV secret at path referenced by the provider

## Architecture

```
Pod (SA: my-app)  →  CSI Node  →  knxvault-csi provider
                                      ↓ TokenReview + role
                                   KNXVault API
                                      ↓
                              files at /mnt/secrets/
```

## Step 1 — Install Secrets Store CSI driver

```bash
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system \
  --set syncSecret.enabled=true \
  --set enableSecretRotation=true
```

## Step 2 — Deploy KNXVault CSI provider

```bash
kubectl apply -f deployments/csi/rbac.yaml
kubectl apply -f deployments/csi/k8s-provider.yaml

kubectl -n knxvault wait --for=condition=available deployment/knxvault-csi-provider --timeout=120s
kubectl -n knxvault logs -l app.kubernetes.io/name=knxvault-csi-provider --tail=20
```

## Step 3 — Seed KV secret

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

knxvault-cli kv put app/db password=supersecret username=appuser host=db.internal
```

## Step 4 — Create SecretProviderClass

```bash
kubectl apply -f - <<'EOF'
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: app-db
  namespace: default
spec:
  provider: knxvault
  rotationPollInterval: 2m
  parameters:
    vaultAddr: "http://knxvault.knxvault.svc.cluster.local:8200"
    role: app-sa
    objects: |
      - path: app/db
        fileName: db.env
        objectType: secret
  secretObjects:
    - secretName: app-db-synced
      type: Opaque
      data:
        - objectName: db.env
          key: db.env
EOF
```

> `secretObjects` syncs to a native Kubernetes `Secret` for `envFrom` — duplicates material in etcd; use only when required.

## Step 5 — Create ServiceAccount and pod

```bash
kubectl create serviceaccount my-app -n default --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: knxvault-csi-demo
  namespace: default
spec:
  serviceAccountName: my-app
  containers:
    - name: app
      image: busybox:1.36
      command: ["sh", "-c", "cat /mnt/secrets/db.env && sleep 3600"]
      volumeMounts:
        - name: secrets
          mountPath: /mnt/secrets
          readOnly: true
  volumes:
    - name: secrets
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: app-db
EOF
```

Ensure KNXVault role `app-sa` binds `my-app` in `default` namespace.

## Step 6 — Verify mount

```bash
kubectl wait --for=condition=ready pod/knxvault-csi-demo --timeout=120s
kubectl exec knxvault-csi-demo -- cat /mnt/secrets/db.env
kubectl get secret app-db-synced -o yaml   # if secretObjects enabled
```

## Step 7 — Test rotation

```bash
knxvault-cli kv put app/db password=rotated-value username=appuser host=db.internal
# Wait rotationPollInterval
kubectl exec knxvault-csi-demo -- cat /mnt/secrets/db.env
```

See [Secret rotation](secret-rotation.md).

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `FailedMount` | Provider logs; role SA binding; KV path exists |
| Empty file | `objectType: secret`; path matches KV layout |
| Auth 403 | [Kubernetes ServiceAccount auth](kubernetes-serviceaccount-auth.md) |
| No rotation | Helm `enableSecretRotation=true`; `rotationPollInterval` set |

## Related recipes

- [Kubernetes ServiceAccount auth](kubernetes-serviceaccount-auth.md)
- [Mutating webhook injection](mutating-webhook-csi-injection.md)
- [Secret rotation](secret-rotation.md)

## See also

- [CSI install runbook](../deploy/csi-install.md)
- [Secrets injection](../deploy/secrets-injection.md)
- Reference manifests: `deployments/csi/`