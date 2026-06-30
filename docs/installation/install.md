# Installation Guide

Install KNXVault as a local binary, container, or 3-node Kubernetes Raft cluster.

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Go | 1.25+ | For building from source (`GOTOOLCHAIN=go1.25.11`) |
| OpenSSL | 3.x | Required for PKI operations |
| Kubernetes | 1.28+ | For production HA deployment |
| Docker | optional | For `make docker-build` |

## Option 1: Local binary (development)

```bash
git clone https://github.com/your-org/knxvault.git
cd knxvault
make build build-cli

export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_ROOT_TOKEN=dev-root-token
./bin/knxvault
```

Verify:

```bash
curl -s http://localhost:8200/health
open http://localhost:8200/swagger   # or visit in browser
```

Without `KNXVAULT_RAFT_ENABLED`, the server uses **in-memory** repositories. Data is lost on restart.

### Single-node Raft (persistent local dev)

```bash
export KNXVAULT_RAFT_ENABLED=true
export KNXVAULT_RAFT_NODE_ID=1
export KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001
export KNXVAULT_RAFT_DATA_DIR=/tmp/knxvault-raft
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001

./bin/knxvault
curl -s http://localhost:8200/ready | jq
```

## Option 2: Docker

```bash
make docker-build

docker run --rm -p 8200:8200 \
  -e KNXVAULT_MASTER_KEY="$(openssl rand -base64 32)" \
  -e KNXVAULT_ROOT_TOKEN=dev-root-token \
  knxvault:0.4.3
```

For persistent Raft data, mount a volume at `/var/lib/knxvault/raft` and set the `KNXVAULT_RAFT_*` variables.

## Option 3: Kubernetes (production)

Production deployments use a **3-replica StatefulSet** with Dragonboat Raft.

```bash
make docker-build
# Push image to your registry and update statefulset.yaml

kubectl apply -f deployments/k8s/namespace.yaml
kubectl apply -f deployments/k8s/serviceaccount.yaml
kubectl apply -f deployments/k8s/role.yaml
kubectl apply -f deployments/k8s/rolebinding.yaml
kubectl apply -f deployments/k8s/configmap.yaml
kubectl apply -f deployments/k8s/secret.yaml
kubectl apply -f deployments/k8s/service-raft.yaml
kubectl apply -f deployments/k8s/statefulset.yaml
kubectl apply -f deployments/k8s/service.yaml
```

Before applying, edit [`deployments/k8s/secret.yaml`](../../deployments/k8s/secret.yaml):

1. `KNXVAULT_MASTER_KEY` — `openssl rand -base64 32`
2. `KNXVAULT_ROOT_TOKEN` — strong bootstrap token
3. `KNXVAULT_AUDIT_SIGNING_KEY` — optional audit export HMAC key

Full details: [Kubernetes deployment](../deploy/kubernetes.md).

## Post-install bootstrap

```bash
export TOKEN=dev-root-token
export ADDR=http://localhost:8200

# Validate token
curl -s -X POST $ADDR/auth/token \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\"}"

# Create a scoped policy (recommended before disabling root token)
curl -s -X PUT $ADDR/sys/policies/app-reader \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"paths":{"secrets/kv/app/*":{"capabilities":["read"]}}}'
```

Or use the CLI:

```bash
export KNXVAULT_ADDR=$ADDR
export KNXVAULT_TOKEN=$TOKEN
./bin/knxvault-cli health
./bin/knxvault-cli kv put app/demo key=value
```

See [Getting started](../user/getting-started.md) for PKI and dynamic secrets workflows.

## Helm

A Helm chart is deferred to long-term future. Use raw manifests in [`deployments/k8s/`](../../deployments/k8s/) until then.

## Next steps

- [Configuration reference](configuration.md) — all environment variables
- [Day-2 operations](../operations/day2.md) — backup, monitoring, upgrades
- [Security model](../architecture/security-model.md) — hardening checklist