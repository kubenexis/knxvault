# Recipe: cert-manager TLS integration

Automate TLS certificate issuance from KNXVault PKI using cert-manager's Vault issuer.

## Prerequisites

- cert-manager installed
- KNXVault PKI role for web servers
- cert-manager ServiceAccount bound to KNXVault role

## Step 1 — PKI and policies

```bash
curl -s -X POST "$KNXVAULT_ADDR/pki/root" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"web-server","common_name":"Web Server CA","ttl":"8760h"}'

curl -s -X PUT "$KNXVAULT_ADDR/sys/policies/cert-manager" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"paths":{"pki/*":{"capabilities":["create","read"]}}}'

curl -s -X PUT "$KNXVAULT_ADDR/sys/roles/cert-manager" \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "policies": ["cert-manager"],
    "bound_service_account_names": ["cert-manager"],
    "bound_service_account_namespaces": ["cert-manager"]
  }'
```

## Step 2 — ClusterIssuer

```bash
kubectl apply -f deployments/cert-manager/clusterissuer-knxvault.yaml
```

KNXVault exposes Vault-compatible paths:

- `POST /v1/auth/kubernetes/login`
- `POST /v1/pki/sign/:role`

## Step 3 — Request certificate

```bash
kubectl apply -f - <<'EOF'
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: demo-tls
  namespace: default
spec:
  secretName: demo-tls
  issuerRef:
    name: knxvault-pki
    kind: ClusterIssuer
  dnsNames:
    - demo.example.com
EOF

kubectl wait --for=condition=ready certificate/demo-tls --timeout=300s
kubectl get secret demo-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -subject
```

## Related recipes

- [PKI issue and revoke](pki-issue-and-revoke.md)
- [Kubernetes ServiceAccount auth](kubernetes-serviceaccount-auth.md)

## See also

- [PKI Kubernetes integration](../operations/pki-kubernetes.md)
- `deployments/cert-manager/`