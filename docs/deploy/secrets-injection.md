<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Secrets injection

KNXVault delivers secrets to Kubernetes workloads through several patterns. **Use the Secrets Store CSI Driver integration first** — it is the primary, Kubernetes-native path. Sidecar and init-container patterns remain available as fallbacks.

## 1. Secrets Store CSI Driver (recommended)

Install the upstream [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/getting-started/installation.html), then deploy the KNXVault CSI provider. See the [CSI install runbook](csi-install.md).

### SecretProviderClass example

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: app-db
  namespace: default
spec:
  provider: knxvault
  parameters:
    vaultAddr: "https://knxvault.knxvault.svc.cluster.local:8200"
    role: app-sa
    objects: |
      - path: app/db
        fileName: db.env
        objectType: secret
  # Optional: sync to a native Secret for envFrom (see W39-06)
  # secretObjects:
  #   - secretName: app-db-synced
  #     type: Opaque
  #     data:
  #       - objectName: db.env
  #         key: db.env
```

### Pod volume mount

```yaml
volumes:
  - name: knxvault-secrets
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: app-db
volumeMounts:
  - name: knxvault-secrets
    mountPath: /mnt/secrets
    readOnly: true
```

The provider exchanges the pod `ServiceAccount` token for a short-lived KNXVault client token (TokenReview — **W36-02**) and fetches KV data at mount time. See [`deployments/csi/`](../../deployments/csi/) for reference manifests.

### Rotation

When KV secrets rotate (**W37-05** / **W39-05**), enable the driver’s rotation poll on the `SecretProviderClass` so mounted files refresh without pod restart.

## 2. Render API (sidecar / init container — fallback)

`POST /inject/render` fetches KV secrets and returns file and environment payloads.

```bash
curl -s -X POST http://localhost:8200/inject/render \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "secrets": [{"path": "app/db", "file_name": "db.env", "env_name": "DB_PASSWORD"}],
    "format": "both"
  }'
```

Requires the `inject-reader` policy (included in `admin`). Use when CSI is not installed or for quick prototypes.

## 3. Sidecar example

See [`deployments/k8s/sidecar-example.yaml`](../../deployments/k8s/sidecar-example.yaml) for a shared `emptyDir` volume populated by a curl sidecar.

## Related

- [Kubernetes deployment](kubernetes.md)
- [Integration overview](../integration/overview.md)
- Backlog: [Tier G — CSI first](../../backlog.md#tier-g--kubernetes-native-consumption-csi-first)