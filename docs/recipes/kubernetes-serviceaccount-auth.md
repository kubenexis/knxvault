# Recipe: Kubernetes ServiceAccount authentication

Create a ServiceAccount, bind it to a KNXVault role, and authenticate from a pod without long-lived vault tokens.

## What you will learn

- How `POST /auth/kubernetes` exchanges a SA JWT for a scoped client token
- Creating policies, roles, and ServiceAccounts end-to-end
- Wiring the same role for CSI and application API access

## Prerequisites

- KNXVault running **in-cluster** (TokenReview RBAC configured)
- `kubectl`, `curl`
- Namespace where your app will run

## Step 1 — Create a read policy

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

curl -s -X PUT "$KNXVAULT_ADDR/sys/policies/app-reader" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "paths": {
      "secrets/kv/app/*": {"capabilities": ["read"]},
      "inject/render": {"capabilities": ["read"]}
    }
  }'
```

See [RBAC policies](rbac-policies.md) for deny rules and admin boundaries.

## Step 2 — Create a role bound to ServiceAccount

```bash
curl -s -X PUT "$KNXVAULT_ADDR/sys/roles/app-sa" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "policies": ["app-reader"],
    "bound_service_account_names": ["my-app"],
    "bound_service_account_namespaces": ["production"]
  }'
```

| Field | Purpose |
|-------|---------|
| `bound_service_account_names` | Only these SA names can use this role |
| `bound_service_account_namespaces` | Only these namespaces |

## Step 3 — Create Kubernetes ServiceAccount

```bash
kubectl create namespace production --dry-run=client -o yaml | kubectl apply -f -

kubectl -n production create serviceaccount my-app
```

## Step 4 — Seed a secret for the app to read

```bash
knxvault-cli kv put app/config api_key=prod-key-12345
```

## Step 5 — Authenticate from a pod

```bash
kubectl -n production apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: knxvault-auth-demo
spec:
  serviceAccountName: my-app
  containers:
    - name: curl
      image: curlimages/curl:8.5.0
      command: ["sleep", "3600"]
EOF

kubectl -n production exec knxvault-auth-demo -- sh -c '
  export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
  JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  RESP=$(curl -s -X POST "$KNXVAULT_ADDR/auth/kubernetes" \
    -H "Content-Type: application/json" \
    -d "{\"role\":\"app-sa\",\"jwt\":\"$JWT\"}")
  echo "$RESP" | jq .
  CLIENT=$(echo "$RESP" | jq -r ".data.token // .token")
  curl -s "$KNXVAULT_ADDR/secrets/kv/app/config" \
    -H "Authorization: Bearer $CLIENT" | jq .
'
```

## Step 6 — Use with CSI provider

The same `app-sa` role name goes in `SecretProviderClass`:

```yaml
parameters:
  vaultAddr: "http://knxvault.knxvault.svc.cluster.local:8200"
  role: app-sa
```

See [CSI driver integration](csi-driver-integration.md).

## Vault-compatible path (cert-manager)

```bash
curl -s -X POST "$KNXVAULT_ADDR/v1/auth/kubernetes/login" \
  -H 'Content-Type: application/json' \
  -d "{\"role\":\"app-sa\",\"jwt\":\"$JWT\"}"
```

## Verify

| Test | Expected |
|------|----------|
| `my-app` in `production` | `200` + client token |
| Wrong SA name | `403` |
| Wrong namespace | `403` |
| Client token reads `app/config` | `200` |
| Client token writes KV | `403` |
| Client token calls `sys/*` | `403` |

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| TokenReview forbidden | KNXVault SA needs `system:auth-delegator` — check `deployments/k8s/role.yaml` |
| `403` with correct SA | Role name mismatch or policy missing path |
| Works with root token only | `KNXVAULT_K8S_AUTH_INSECURE` — disable in production |

## Related recipes

- [Kubernetes auth security](kubernetes-auth-security.md)
- [RBAC policies](rbac-policies.md)
- [CSI driver integration](csi-driver-integration.md)

## See also

- [Integration overview](../integration/overview.md)
- [examples/cli/k8s-login.sh](../../examples/cli/k8s-login.sh)