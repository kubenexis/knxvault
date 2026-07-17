<!--
Copyright Kubenexis Systems Private Limited.
SPDX-License-Identifier: CC-BY-4.0
-->

# Installation Guide

Install KNXVault as a local binary, container, or 3-node Kubernetes Raft cluster.

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Go | 1.26.5+ | For building from source (`GOTOOLCHAIN=go1.26.5`) |
| OpenSSL | — | **Not used by the server.** Optional on admin hosts for `openssl rand` key generation only. |
| Kubernetes | 1.28+ | For production HA deployment (**3 nodes** for Raft quorum) |
| Docker or nerdctl | for packaging | `make container-build` → distroless `static-debian13` server image; see [Build and deploy images](../operations/build-and-deploy-images.md) |

## Option 1: Local binary (development)

In-memory mode (data lost on restart). Suitable for local CLI exploration:

```bash
git clone https://github.com/your-org/knxvault.git
cd knxvault
make build build-cli

export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_ROOT_TOKEN=dev-root-token
./build/bin/knxvault serve
```

Without `KNXVAULT_RAFT_ENABLED`, the server uses **in-memory** repositories. Data is lost on restart.

When `/etc/knxvault.conf` exists, `knxvault serve` loads it automatically. Override with `knxvault -c /path/knxvault.conf serve`. See [Configuration reference](configuration.md).

### Single-node Raft (persistent local / lab)

Use this for persistent local dev or a **single bare-metal lab host**. This is **not** HA: failover and multi-replica quorum still require three Raft peers (Option 3 or multi-process Profile A in [manual testing](../engineering/manual-testing-strategy.md)).

When Raft is enabled, **`KNXVAULT_UNSEAL_KEY` is required** at startup and must be a base64-encoded 32-byte key **different from** `KNXVAULT_MASTER_KEY`. If it is unset (or equal to the master key), `serve` exits immediately with:

```text
unseal key is required when raft is enabled (set KNXVAULT_UNSEAL_KEY)
```

```bash
export KNXVAULT_MASTER_KEY=$(openssl rand -base64 32)
export KNXVAULT_UNSEAL_KEY=$(openssl rand -base64 32)   # required; must differ from master
export KNXVAULT_ROOT_TOKEN=dev-root-token
export KNXVAULT_RAFT_ENABLED=true
export KNXVAULT_RAFT_NODE_ID=1
export KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001
export KNXVAULT_RAFT_DATA_DIR=/tmp/knxvault-raft   # or a durable path such as /var/lib/knxvault/raft
export KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001

./build/bin/knxvault serve
```

Bare-metal lab smoke (host binary, single-node Raft):

- **Full suite (Shamir multi-share unseal + core + Vault profile + operator):** `make lab-full-e2e` → [lab-full-e2e.md](../engineering/lab-full-e2e.md) (**53/53 PASS**)
- Test map: [E2E and lab tests](../engineering/e2e-and-lab-tests.md)
- Core-only historical record: [Lab E2E e2e-test01](../engineering/lab-e2e-test01.md)

After any Raft start, **unseal** (full key or multi-share) before writes — process starts sealed when unseal key is set. Recipe: [Seal and unseal](../recipes/seal-and-unseal.md).

## Option 2: Docker / containerd (distroless Debian 13)

**Build catalog, image matrix, and containerd (`nerdctl`) deploy steps:**  
[Build and deploy images](../operations/build-and-deploy-images.md).

**Always** build knxvault as the multi-stage image in `Dockerfile`:

| Stage | Base | Purpose |
|-------|------|---------|
| builder | `golang:1.26-bookworm` | Static `CGO_ENABLED=0` binaries |
| runtime | `gcr.io/distroless/static-debian13:nonroot` | Minimal non-root runtime (no shell, no OpenSSL) |

PKI is always native Go `crypto/x509` (OpenSSL CLI backend removed). See [PKI native only](../operations/pki-openssl-migration.md).

In-memory (or default) container:

```bash
make container-build   # uses docker or nerdctl → ghcr.io/kubenexis/knxvault:0.5.1

docker run --rm -p 8200:8200 \
  -e KNXVAULT_MASTER_KEY="$(openssl rand -base64 32)" \
  -e KNXVAULT_ROOT_TOKEN=dev-root-token \
  ghcr.io/kubenexis/knxvault:0.5.1 serve
```

For **persistent single-node Raft**, mount a data volume and set unseal + Raft env (unseal must differ from master):

```bash
MASTER=$(openssl rand -base64 32)
UNSEAL=$(openssl rand -base64 32)

docker run --rm -p 8200:8200 \
  -v knxvault-raft:/var/lib/knxvault/raft \
  -e KNXVAULT_MASTER_KEY="$MASTER" \
  -e KNXVAULT_UNSEAL_KEY="$UNSEAL" \
  -e KNXVAULT_ROOT_TOKEN=dev-root-token \
  -e KNXVAULT_RAFT_ENABLED=true \
  -e KNXVAULT_RAFT_NODE_ID=1 \
  -e KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001 \
  -e KNXVAULT_RAFT_DATA_DIR=/var/lib/knxvault/raft \
  -e KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001 \
  ghcr.io/kubenexis/knxvault:0.5.1 serve
```

For a **full standalone Day-0 + Day-2 story** (distroless container + host `knxvault-cli`, no Kubernetes), see:

**[Standalone distroless + host CLI (Day-0 / Day-2)](../operations/standalone-distroless-day0-day2.md)**

Kubernetes platform Day-0/Day-2: [operator runbook](../operations/operator-runbook.md).

## Option 3: Kubernetes (production HA)

Production deployments use a **3-replica StatefulSet** with Dragonboat Raft. A single lab node is **not** sufficient for production HA smoke (three peers need scheduling capacity and PVCs). For single-host validation use Option 1 single-node Raft or the [lab E2E](../engineering/lab-e2e-test01.md).

**Day-0 / Day-2 with host CLI** (port-forward or Service URL, unseal, doctor, KV/PKI):  
[Kubernetes CLI Day-0 / Day-2](../operations/kubernetes-cli-day0-day2.md). Full platform narrative: [operator runbook](../operations/operator-runbook.md).

```bash
make container-build
# Push image to your registry and update statefulset.yaml

kubectl apply -f deployments/k8s/namespace.yaml
kubectl apply -f deployments/k8s/serviceaccount.yaml
kubectl apply -f deployments/k8s/role.yaml
kubectl apply -f deployments/k8s/rolebinding.yaml
kubectl apply -f deployments/k8s/clusterrole-tokenreview.yaml
kubectl apply -f deployments/k8s/configmap.yaml
kubectl apply -f deployments/k8s/secret.yaml
kubectl apply -f deployments/k8s/service-raft.yaml
kubectl apply -f deployments/k8s/statefulset.yaml
kubectl apply -f deployments/k8s/service.yaml
```

Before applying, edit [`deployments/k8s/secret.yaml`](../../deployments/k8s/secret.yaml):

1. `KNXVAULT_MASTER_KEY` — `openssl rand -base64 32` (envelope encryption)
2. `KNXVAULT_UNSEAL_KEY` — `openssl rand -base64 32` (**required** with Raft; **must differ** from master)
3. `KNXVAULT_ROOT_TOKEN` — strong bootstrap token
4. `KNXVAULT_AUDIT_SIGNING_KEY` — optional audit export HMAC key

The StatefulSet loads all Secret keys via `envFrom.secretRef`. Full details: [Kubernetes deployment](../deploy/kubernetes.md).

## Post-install verify

Run after every install (local, Docker, or port-forward to the Service). Prefer the CLI when available.

```bash
export KNXVAULT_ADDR=http://localhost:8200
export KNXVAULT_TOKEN=dev-root-token   # or your bootstrap token

# 1. Liveness
curl -s "$KNXVAULT_ADDR/health"
# expect: "status":"healthy"

# 2. Readiness — production fields when Raft is on
curl -s "$KNXVAULT_ADDR/ready"
# expect: "status":"ready", "sealed":false
# with Raft: "raft_enabled":true, "raft_ready":true, "leader":true (on the leader)

# 3. Full operator/CLI gate (recommended)
./build/bin/knxvault-cli doctor --json
# expect: "healthy": true, "fail": 0
# lab-only warn: API traffic over http (use https in production)
```

| Field on `/ready` | Meaning |
|-------------------|---------|
| `status` | `ready` when the node can accept traffic |
| `sealed` | Must be `false` for writes |
| `raft_enabled` | Dragonboat backend is configured |
| `raft_ready` | Raft cluster has a leader / is usable |
| `leader` | This process is the Raft leader (jobs run here) |

Also confirm OpenAPI and metrics if you expose them operationally:

```bash
curl -sf -o /dev/null -w "%{http_code}\n" "$KNXVAULT_ADDR/openapi.yaml"   # 200
curl -sf "$KNXVAULT_ADDR/metrics" | head -n 5
```

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

# Optional: Vault product profile health (cert-manager Ready probe)
curl -sS -o /dev/null -w "%{http_code}\n" "$ADDR/v1/sys/health"   # expect 200
```

For **Kubernetes TLS without cert-manager**, install the operator CRDs after the vault cluster is healthy:

```bash
kubectl apply -f deployments/operator/crds/
kubectl apply -f deployments/operator/rbac.yaml
# see docs/operations/pki-replace-cert-manager.md
```

Or use the CLI:

```bash
export KNXVAULT_ADDR=$ADDR
export KNXVAULT_TOKEN=$TOKEN
./build/bin/knxvault-cli health
./build/bin/knxvault-cli doctor
./build/bin/knxvault-cli kv put app/demo key=value
./build/bin/knxvault-cli kv get app/demo --show-secrets
```

See [Getting started](../user/getting-started.md) for PKI and dynamic secrets workflows.

## Helm

A Helm chart is deferred to long-term future. Use raw manifests in [`deployments/k8s/`](../../deployments/k8s/) until then.

## knxvault-operator (TLS without cert-manager)

After the vault API is up, install CRD automation so workloads get `kubernetes.io/tls` Secrets from KNXVault PKI **without cert-manager**:

```bash
make build-operator
kubectl apply -f deployments/operator/crds/
kubectl apply -f deployments/operator/rbac.yaml
# run operator with KNXVAULT_ADDR + KNXVAULT_TOKEN (see deployments/operator/deployment.yaml)
kubectl apply -f deployments/operator/samples/certificate-example.yaml
```

Guide: [Replacing cert-manager with KNXVault](../operations/pki-replace-cert-manager.md). Lab e2e: `bash scripts/lab-operator-e2e.sh <kube-node>`.

## Next steps

- [Configuration reference](configuration.md) — all environment variables (including unseal + Raft)
- [Local dev single-node recipe](../recipes/local-dev-single-node.md)
- [Replace cert-manager](../operations/pki-replace-cert-manager.md) — operator CRDs (W30)
- [Operator security](../operations/operator-security.md) — key custody checklist
- [Day-2 operations](../operations/day2.md) — backup, monitoring, upgrades
- [Security model](../architecture/security-model.md) — hardening checklist
