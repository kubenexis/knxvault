# Recipe: Mutating webhook CSI injection

Inject Secrets Store CSI volumes into pods using annotations — no hand-written volume blocks.

## Prerequisites

- CSI driver and [knxvault-csi provider](csi-driver-integration.md) installed
- `SecretProviderClass` exists

## Deploy webhook

```bash
kubectl label namespace default knxvault.io/webhook=enabled --overwrite

kubectl apply -f deployments/k8s/webhook/deployment.yaml
kubectl apply -f deployments/k8s/webhook/mutating-webhook.yaml

kubectl -n knxvault wait --for=condition=available deployment/knxvault-webhook --timeout=120s
```

## Create pod with annotations

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: webhook-demo
  namespace: default
  annotations:
    knxvault.io/inject: "true"
    knxvault.io/secret-provider-class: app-db
    knxvault.io/inject-mount-path: /mnt/secrets
spec:
  serviceAccountName: my-app
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
```

```bash
kubectl apply -f pod.yaml
kubectl get pod webhook-demo -o json | jq '.spec.volumes'
kubectl exec webhook-demo -- ls /mnt/secrets
```

## Required annotations

| Annotation | Required | Default |
|------------|----------|---------|
| `knxvault.io/inject` | Yes | — must be `"true"` |
| `knxvault.io/secret-provider-class` | Yes | — |
| `knxvault.io/inject-mount-path` | No | `/mnt/knxvault-secrets` |

## Namespace gating

Only namespaces labeled `knxvault.io/webhook=enabled` are mutated.

## Related recipes

- [CSI driver integration](csi-driver-integration.md)

## See also

- [Kubernetes-native integrations](../integration/kubernetes-native.md)