<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Build images and deploy (containerd standalone + Kubernetes)

How to **build** knxvault container images, **which images** each topology needs, and **deployment steps**. Standalone steps assume **containerd + nerdctl** (not Docker Engine). Kubernetes steps assume a registry and `kubectl`.

| Field | Value |
|-------|-------|
| **Build host** | Repo checkout, Go 1.26+ (Makefile `GOTOOLCHAIN`), **nerdctl** or docker |
| **Server runtime base** | `gcr.io/distroless/static-debian13:nonroot` only |
| **Admin tool** | Host binary `knxvault-cli` — **not** an image |
| **Related** | [Standalone Day-0/Day-2](standalone-distroless-day0-day2.md) · [K8s CLI Day-0/Day-2](kubernetes-cli-day0-day2.md) |

---

## 1. Image catalog

### Images you build from this repo

| Image (default tag) | Dockerfile | Makefile | Binaries inside | Used for |
|---------------------|------------|----------|-----------------|----------|
| **`knxvault:$(VERSION)-$(COMMIT)`** (e.g. `knxvault:0.5.1-a1b2c3d`) | `Dockerfile` | `make container-build` | `knxvault`, `knxvault-csi`, `knxvault-webhook`, `knxvault-eso` | Server (always); CSI / webhook / ESO adapters by **command override** |
| **`knxvault-operator:$(VERSION)-$(COMMIT)`** | `Dockerfile.operator` | `make k8s-operator-build` | `knxvault-operator` | Kubernetes certificate operator only |

**Identity:** image tags and export tarball names use **`IMAGE_TAG = VERSION-COMMIT`** (short git SHA) so each build is unique. Builds also apply a floating alias **`knxvault:VERSION`** / **`knxvault-operator:VERSION`** for local manifests that pin only the semver.

```bash
# Default: knxvault:0.5.1-<shortsha>  (+ alias knxvault:0.5.1)
make container-build
make k8s-operator-build
make container-build-all

# Registry with commit identity
make container-build IMAGE=registry.example.com/knxvault:0.5.1-$(git rev-parse --short HEAD)
# or both with explicit version:
make container-build-all VERSION=0.5.1
```

Default entrypoint of `knxvault:…` is **`/usr/local/bin/knxvault`** with `CMD ["serve"]`. Other binaries share the same image:

| Workload | Manifest | Command / entrypoint |
|----------|----------|----------------------|
| Vault server | `deployments/k8s/statefulset.yaml` | default `knxvault serve` |
| CSI provider | `deployments/csi/k8s-provider.yaml` | `command: ["/usr/local/bin/knxvault-csi"]` |
| Mutating webhook | `deployments/k8s/webhook/deployment.yaml` | `command: ["/usr/local/bin/knxvault-webhook"]` |
| ESO adapter | `deployments/external-secrets/knxvault-eso-deployment.yaml` | `command: ["/usr/local/bin/knxvault-eso"]` |
| Operator | `deployments/operator/deployment.yaml` | **separate** image `knxvault-operator:…` |

### Not container images

| Artifact | Build | Deploy |
|----------|-------|--------|
| **`knxvault-cli`** | `make build-cli` → `build/bin/knxvault-cli` | Copy to admin host / package as `.deb` later; never baked into distroless server |
| Host server binary (optional) | `make build` → `build/bin/knxvault` | Bare-metal only; **not** the supported production packaging path |

### Third-party / platform images (not built here)

| Image | When needed |
|-------|-------------|
| `gcr.io/distroless/static-debian13:nonroot` | **Build-time** base (pulled during `container-build`) |
| `golang:1.26-bookworm` | **Build-time** builder stage |
| Secrets Store CSI Driver images | Only if you install CSI (upstream driver) |
| `busybox`, `curlimages/curl` | Example/sidecar manifests only — not required for core vault |

---

## 2. What you need by topology

### A. Standalone (containerd + nerdctl) — **minimum**

| Required | Optional |
|----------|----------|
| Image **`knxvault:<version>`** loaded into containerd | — |
| Host **`knxvault-cli`** | HTTPS reverse proxy in front of `:8200` |
| Host paths / volume for Raft data | Multi-node Raft peers (advanced) |

**Not required:** `knxvault-operator`, CSI, webhook, ESO, Kubernetes.

### B. Kubernetes — **minimum HA vault**

| Required | Optional (same `knxvault` image, different command) | Separate image |
|----------|------------------------------------------------------|----------------|
| **`knxvault:<version>`** for StatefulSet | CSI provider DaemonSet | **`knxvault-operator:<version>`** for cert CRDs |
| Registry pull (or preloaded nodes) | Mutating webhook | — |
| Host **`knxvault-cli`** for admin | ESO adapter | — |
| StorageClass + Secret + RBAC | Example sidecars (`busybox` / `curl`) | — |

Manifests set `image: knxvault:0.5.1` / `knxvault-operator:0.5.1` with `imagePullPolicy: IfNotPresent` in several places — retag to your registry for real clusters.

---

## 3. How to build

### 3.1 Prerequisites

```bash
# On the build host
command -v go
command -v nerdctl || command -v docker
# Prefer nerdctl when the runtime is containerd
```

**Container CLI selection (`make container-build`):**

| Order | Backend | When |
|-------|---------|------|
| 1 | `docker` | `docker info` succeeds |
| 2 | `nerdctl` | rootless/rootful `nerdctl info` succeeds |
| 3 | `sudo nerdctl` | rootful containerd (common on build hosts) |

If you see `rootless containerd not running`, either start rootless containerd or force rootful:

```bash
make container-build-all DOCKER='sudo nerdctl'
# or permanently: export DOCKER='sudo nerdctl'
```

Pull bases once (air-gap: transfer these layers too):

```bash
# example with nerdctl (use sudo if rootful containerd)
sudo nerdctl pull golang:1.26-bookworm
sudo nerdctl pull gcr.io/distroless/static-debian13:nonroot
```

### 3.2 Build server image

```bash
cd /path/to/knxvault
make container-build
# → knxvault:0.5.1  (or IMAGE=…)
```

`make container-build` auto-picks a **working** `docker` / `nerdctl` / `sudo nerdctl` (see above).

### 3.3 Build operator image (Kubernetes TLS automation)

```bash
make k8s-operator-build
# → knxvault-operator:0.5.1
```

### 3.4 Build host CLI

```bash
make build-cli
# → build/bin/knxvault-cli
```

### 3.5 Air-gap / export images as tarballs

Export targets **rebuild images first**, so `make clean container-export-all` is valid.

```bash
# Rebuild (if needed) + export (recommended one-liner)
make container-export-all
# → build/images/knxvault-0.5.1-<commit>.tar
# → build/images/knxvault-operator-0.5.1-<commit>.tar
# → build/images/build-info-0.5.1-<commit>.txt

# Individual targets (each depends on matching *-build)
make container-export          # server only (standalone)
make k8s-operator-export       # operator only (K8s)

# Overrides
make container-export-all IMAGE_EXPORT_DIR=/tmp/airgap VERSION=0.5.1
# IMAGE_TAG defaults to $(VERSION)-$(COMMIT)
```

| Topology | Tarballs required |
|----------|-------------------|
| **Standalone** containerd | `knxvault-$(IMAGE_TAG).tar` only |
| **Kubernetes** (vault only) | `knxvault-$(IMAGE_TAG).tar` on every node (or registry) |
| **Kubernetes** + operator | both server + operator tarballs for that `IMAGE_TAG` |

**On the air-gapped target** (same engine as build when possible):

```bash
# containerd / nerdctl — use exact names from build-info-*.txt
sudo nerdctl load -i build/images/knxvault-0.5.1-<commit>.tar
sudo nerdctl load -i build/images/knxvault-operator-0.5.1-<commit>.tar   # if K8s operator
sudo nerdctl images | grep knxvault
# optional alias for manifests that pin knxvault:0.5.1
# sudo nerdctl tag knxvault:0.5.1-<commit> knxvault:0.5.1

# Docker Engine
docker load -i build/images/knxvault-0.5.1-<commit>.tar
```

Also ship **host `knxvault-cli`** (`make build-cli` → copy `build/bin/knxvault-cli`) — not an image.

Kubernetes nodes: load into each node’s containerd **or** push to an internal registry and set `image:` on manifests.

### 3.6 Registry push (Kubernetes)

```bash
REG=registry.example.com/knx
nerdctl tag knxvault:0.5.1 ${REG}/knxvault:0.5.1
nerdctl tag knxvault-operator:0.5.1 ${REG}/knxvault-operator:0.5.1
nerdctl push ${REG}/knxvault:0.5.1
nerdctl push ${REG}/knxvault-operator:0.5.1
# Update image: fields in StatefulSet / operator Deployment
```

---

## 4. Standalone deployment (containerd + nerdctl)

End-to-end ops narrative: [standalone-distroless-day0-day2.md](standalone-distroless-day0-day2.md). Below is the **image-focused** deploy sequence.

### 4.1 One-time on the host

```bash
# build or load knxvault:0.5.1 into this host's containerd
make container-build    # or nerdctl load -i knxvault-0.5.1.tar
make build-cli

mkdir -p /var/lib/knxvault/raft
chmod 700 /var/lib/knxvault/raft

# offline keys (do not commit)
MASTER=$(openssl rand -base64 32)
UNSEAL=$(openssl rand -base64 32)   # must differ from MASTER
ROOT=$(openssl rand -base64 24)
# save MASTER UNSEAL ROOT offline
```

### 4.2 Run the server container

```bash
nerdctl run -d --name knxvault --restart=unless-stopped \
  -p 8200:8200 \
  -v /var/lib/knxvault/raft:/var/lib/knxvault/raft \
  -e KNXVAULT_MASTER_KEY="$MASTER" \
  -e KNXVAULT_UNSEAL_KEY="$UNSEAL" \
  -e KNXVAULT_ROOT_TOKEN="$ROOT" \
  -e KNXVAULT_RAFT_ENABLED=true \
  -e KNXVAULT_RAFT_NODE_ID=1 \
  -e KNXVAULT_RAFT_ADDRESS=127.0.0.1:63001 \
  -e KNXVAULT_RAFT_DATA_DIR=/var/lib/knxvault/raft \
  -e KNXVAULT_RAFT_INITIAL_MEMBERS=1=127.0.0.1:63001 \
  knxvault:0.5.1 serve
```

Lab without persistence (data lost on stop):

```bash
nerdctl run -d --name knxvault -p 8200:8200 \
  -e KNXVAULT_MASTER_KEY="$MASTER" \
  -e KNXVAULT_ROOT_TOKEN="$ROOT" \
  knxvault:0.5.1 serve
```

### 4.3 Admin from the host (CLI, not exec)

```bash
export KNXVAULT_ADDR=http://127.0.0.1:8200
export KNXVAULT_TOKEN="$ROOT"

./build/bin/knxvault-cli sys unseal "$UNSEAL"   # Raft path
./build/bin/knxvault-cli doctor --json
./build/bin/knxvault-cli health
```

Do **not** `nerdctl exec` into the distroless image for administration.

### 4.4 Lifecycle

```bash
nerdctl logs -f knxvault
nerdctl stop knxvault && nerdctl start knxvault   # then unseal again if Raft
nerdctl rm -f knxvault                            # volume data remains on host path
```

Upgrade:

```bash
# load/build new tag, stop old, run new with same -v and env, unseal, doctor
```

---

## 5. Kubernetes deployment (image-focused)

Full Day-0/Day-2: [kubernetes-cli-day0-day2.md](kubernetes-cli-day0-day2.md), [operator-runbook.md](operator-runbook.md).

### 5.1 Minimum vault (3-node Raft)

**Images**

1. Build/push **`knxvault:<version>`** only.  
2. Set `image:` in `deployments/k8s/statefulset.yaml`.  
3. Apply core manifests (namespace → RBAC → configmap → secret → services → statefulset).  
4. Port-forward or internal URL + **host CLI** unseal/doctor.

### 5.2 With certificate operator

**Images**

1. `knxvault:<version>` (STS)  
2. `knxvault-operator:<version>` (`make k8s-operator-build`, push, set `deployments/operator/deployment.yaml`)  

Then CRDs + operator RBAC + Deployment + sample Certificate CRDs.

### 5.3 Optional add-ons (reuse `knxvault` image)

| Add-on | Extra image build? | Notes |
|--------|--------------------|--------|
| CSI provider | No — same `knxvault` image | Needs **Secrets Store CSI Driver** (third-party images) |
| Webhook | No | `command: knxvault-webhook` |
| ESO adapter | No | Plus External Secrets Operator in the cluster |

### 5.4 Image checklist matrix

| Component | Standalone containerd | K8s min HA | K8s + operator | K8s + CSI |
|-----------|:---------------------:|:----------:|:--------------:|:---------:|
| `knxvault:…` | **Yes** | **Yes** | **Yes** | **Yes** |
| `knxvault-operator:…` | No | No | **Yes** | No* |
| Host `knxvault-cli` | **Yes** | **Yes** | **Yes** | **Yes** |
| Host ACME profiles (`examples/acme/`) | Optional (public TLS) | Optional (edge TLS) | Optional | Optional |
| Upstream CSI driver images | No | No | No | **Yes** |

**Public TLS note:** Let's Encrypt automation runs on the **host CLI** (`knxvault-cli acme`) or **operator ACME CRDs** — never inside the distroless `knxvault` server image.

\*CSI does not require the operator image.

---

## 6. Verify image contents (optional)

```bash
# Inspect config (nerdctl)
nerdctl image inspect knxvault:0.5.1 --format '{{.Config.Entrypoint}} {{.Config.Cmd}} {{.Config.User}}'

# Run one-shot (no serve): version
nerdctl run --rm --entrypoint /usr/local/bin/knxvault knxvault:0.5.1 -version
```

Expect non-root user, entrypoint `knxvault`, no shell.

---

## 7. Related documents

| Topic | Document |
|-------|----------|
| Standalone ops (unseal, smoke, Day-2) | [standalone-distroless-day0-day2.md](standalone-distroless-day0-day2.md) |
| K8s ops with CLI | [kubernetes-cli-day0-day2.md](kubernetes-cli-day0-day2.md) |
| K8s platform narrative | [operator-runbook.md](operator-runbook.md) |
| Install overview | [installation/install.md](../installation/install.md) |
| CLI flags | [cli/reference.md](../cli/reference.md) |
| Env vars | [installation/configuration.md](../installation/configuration.md) |
| PKI / distroless policy | [pki-openssl-migration.md](pki-openssl-migration.md) |

---

## 8. Quick reference

```bash
# Build everything you need for both topologies
make container-build              # knxvault:VERSION  (standalone + K8s server/CSI/webhook/ESO)
make k8s-operator-build           # knxvault-operator:VERSION  (K8s operator only)
make container-build-all          # both images
make container-export-all         # air-gap: build/images/*-$(VERSION)-$(COMMIT).tar + build-info-*.txt
make build-cli                    # host admin binary

# Air-gap load (target host)
sudo nerdctl load -i build/images/knxvault-0.5.1-<commit>.tar
sudo nerdctl load -i build/images/knxvault-operator-0.5.1-<commit>.tar   # K8s operator

# Standalone (containerd)
nerdctl run -d --name knxvault -p 8200:8200 … knxvault:0.5.1 serve
export KNXVAULT_ADDR=http://127.0.0.1:8200
./build/bin/knxvault-cli sys unseal "$UNSEAL"

# Kubernetes
# load or push images → set image: → kubectl apply → port-forward → knxvault-cli unseal/doctor
```
