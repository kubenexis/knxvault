<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Recipe: Secret rotation

Rotate KV secrets on a schedule and deliver updated values to running pods without restart.

## What you will learn

- Scheduled KV rotation via `PUT /sys/kv-rotation`
- How the Secrets Store CSI driver polls for new versions
- Measuring rotation-to-pod latency

## Prerequisites

- 3-node cluster or single-node dev instance
- [CSI driver integration](csi-driver-integration.md) completed (for pod refresh without restart)
- Admin token

## Concepts

| Layer | What rotates | Who triggers |
|-------|--------------|--------------|
| **KV version** | New secret version at same path | Operator, API, or `sys/kv-rotation` schedule |
| **CSI mount** | File content on running pod | Driver `rotationPollInterval` polling |
| **Orchestrated** | KV + database + PKI targets | `POST /sys/rotation/run` on Raft leader — see [Orchestrated rotation](orchestrated-rotation.md) |

Rotation does **not** automatically change application behavior until the workload reloads the secret (CSI polling, sidecar, or app signal).

## Step 1 — Store an initial secret

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

knxvault-cli kv put app/credentials password=version-1 api_key=key-v1
```

## Step 2 — Configure KV rotation schedule (optional)

```bash
curl -s -X PUT "$KNXVAULT_ADDR/sys/kv-rotation" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "path": "app/credentials",
    "interval_seconds": 3600,
    "template": {
      "password": "{{ random \"alnum\" 32 }}",
      "api_key": "{{ random \"alnum\" 64 }}"
    }
  }' | jq .
```

The Raft leader runs the rotation job on each tick. Remove the schedule:

```bash
curl -s -X DELETE "$KNXVAULT_ADDR/sys/kv-rotation" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN"
```

## Step 3 — Manual rotation (immediate)

```bash
knxvault-cli kv put app/credentials password=version-2 api_key=key-v2

# Confirm new version
curl -s "$KNXVAULT_ADDR/secrets/kv/app/credentials/versions" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" | jq .
```

## Step 4 — CSI rotation polling

Install the CSI driver with rotation enabled:

```bash
helm upgrade --install csi secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system \
  --set syncSecret.enabled=true \
  --set enableSecretRotation=true
```

Set `rotationPollInterval` on the `SecretProviderClass`:

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: app-creds
spec:
  provider: knxvault
  rotationPollInterval: 30s
  parameters:
    vaultAddr: "http://knxvault.knxvault.svc.cluster.local:8200"
    role: app-sa
    objects: |
      - path: app/credentials
        fileName: creds.json
        objectType: secret
```

Deploy a pod that tails the mount:

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: rotation-demo
spec:
  serviceAccountName: app-sa
  containers:
    - name: watcher
      image: busybox:1.36
      command: ["sh", "-c", "while true; do cat /mnt/secrets/creds.json; sleep 10; done"]
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
          secretProviderClass: app-creds
EOF
```

## Step 5 — Measure latency

```bash
# T_rotate: note time when you rotate
knxvault-cli kv put app/credentials password=version-3 api_key=key-v3

# Watch pod logs until version-3 appears (T_visible)
kubectl logs rotation-demo -f
```

**Target:** median latency ≤ `rotationPollInterval` + 15 seconds (no pod restart).

## Verify

```bash
kubectl exec rotation-demo -- cat /mnt/secrets/creds.json
# Contains version-3 values

curl -s "$KNXVAULT_ADDR/audit/export?limit=10" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  | jq '.entries | map(select(.resource|contains("app/credentials")))'
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Pod still shows old value | Confirm `enableSecretRotation=true` on Helm chart; check `rotationPollInterval` |
| Rotation job not running | Only Raft leader runs schedules — check `knxvault_raft_leader` metric |
| 403 on CSI mount | Role SA binding — see [Kubernetes ServiceAccount auth](kubernetes-serviceaccount-auth.md) |

## Related recipes

- [KV secrets lifecycle](kv-secrets-lifecycle.md)
- [CSI driver integration](csi-driver-integration.md)
- [Orchestrated rotation](orchestrated-rotation.md)

## See also

- [Secrets injection](../deploy/secrets-injection.md)
- [Manual testing MT-02](../engineering/manual-testing-strategy.md)