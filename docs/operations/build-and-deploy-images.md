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
| **`knxvault:0.4.5`** | `Dockerfile` | `make docker-build` | `knxvault`, `knxvault-csi`, `knxvault-webhook`, `knxvault-eso` | Server (always); CSI / webhook / ESO adapters by **command override** |
| **`knxvault-operator:0.4.5`** | `Dockerfile.operator` | `make docker-build-operator` | `knxvault-operator` | Kubernetes certificate operator only |

Version comes from Makefile `VERSION` (default `0.4.5`). Override:

```bash
make docker-build IMAGE=registry.example.com/knxvault:0.4.5
make docker-build-operator OPERATOR_IMAGE=registry.example.com/knxvault-operator:0.4.5
# or both:
make docker-build-all VERSION=0.4.5
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
| **`knxvault-cli`** | `make build-cli` → `bin/knxvault-cli` | Copy to admin host / package as `.deb` later; never baked into distroless server |
| Host server binary (optional) | `make build` → `bin/knxvault` | Bare-metal only; **not** the supported production packaging path |

### Third-party / platform images (not built here)

| Image | When needed |
|-------|-------------|
| `gcr.io/distroless/static-debian13:nonroot` | **Build-time** base (pulled during `docker-build`) |
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

Manifests set `image: knxvault:0.4.5` / `knxvault-operator:0.4.5` with `imagePullPolicy: IfNotPresent` in several places — retag to your registry for real clusters.

---

## 3. How to build

### 3.1 Prerequisites

```bash
# On the build host
command -v go
command -v nerdctl || command -v docker
# Prefer nerdctl when the runtime is containerd
```

**Container CLI selection (`make docker-build`):**

| Order | Backend | When |
|-------|---------|------|
| 1 | `docker` | `docker info` succeeds |
| 2 | `nerdctl` | rootless/rootful `nerdctl info` succeeds |
| 3 | `sudo nerdctl` | rootful containerd (common on build hosts) |

If you see `rootless containerd not running`, either start rootless containerd or force rootful:

```bash
make docker-build-all DOCKER='sudo nerdctl'
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
make docker-build
# → knxvault:0.4.5  (or IMAGE=…)
```

`make docker-build` auto-picks a **working** `docker` / `nerdctl` / `sudo nerdctl` (see above).

### 3.3 Build operator image (Kubernetes TLS automation)

```bash
make docker-build-operator
# → knxvault-operator:0.4.5
```

### 3.4 Build host CLI

```bash
make build-cli
# → bin/knxvault-cli
```

### 3.5 Air-gap / move images to another host

```bash
# On build host
nerdctl save -o knxvault-0.4.5.tar knxvault:0.4.5
nerdctl save -o knxvault-operator-0.4.5.tar knxvault-operator:0.4.5

# On target (containerd)
nerdctl load -i knxvault-0.4.5.tar
nerdctl load -i knxvault-operator-0.4.5.tar
nerdctl images | grep knxvault
```

Kubernetes nodes: load into each node’s containerd **or** push to an internal registry and set `image:` on manifests.

### 3.6 Registry push (Kubernetes)

```bash
REG=registry.example.com/knx
nerdctl tag knxvault:0.4.5 ${REG}/knxvault:0.4.5
nerdctl tag knxvault-operator:0.4.5 ${REG}/knxvault-operator:0.4.5
nerdctl push ${REG}/knxvault:0.4.5
nerdctl push ${REG}/knxvault-operator:0.4.5
# Update image: fields in StatefulSet / operator Deployment
```

---

## 4. Standalone deployment (containerd + nerdctl)

End-to-end ops narrative: [standalone-distroless-day0-day2.md](standalone-distroless-day0-day2.md). Below is the **image-focused** deploy sequence.

### 4.1 One-time on the host

```bash
# build or load knxvault:0.4.5 into this host's containerd
make docker-build    # or nerdctl load -i knxvault-0.4.5.tar
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
  knxvault:0.4.5 serve
```

Lab without persistence (data lost on stop):

```bash
nerdctl run -d --name knxvault -p 8200:8200 \
  -e KNXVAULT_MASTER_KEY="$MASTER" \
  -e KNXVAULT_ROOT_TOKEN="$ROOT" \
  knxvault:0.4.5 serve
```

### 4.3 Admin from the host (CLI, not exec)

```bash
export KNXVAULT_ADDR=http://127.0.0.1:8200
export KNXVAULT_TOKEN="$ROOT"

./bin/knxvault-cli sys unseal "$UNSEAL"   # Raft path
./bin/knxvault-cli doctor --json
./bin/knxvault-cli health
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
2. `knxvault-operator:<version>` (`make docker-build-operator`, push, set `deployments/operator/deployment.yaml`)  

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
nerdctl image inspect knxvault:0.4.5 --format '{{.Config.Entrypoint}} {{.Config.Cmd}} {{.Config.User}}'

# Run one-shot (no serve): version
nerdctl run --rm --entrypoint /usr/local/bin/knxvault knxvault:0.4.5 -version
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
make docker-build              # knxvault:VERSION  (standalone + K8s server/CSI/webhook/ESO)
make docker-build-operator     # knxvault-operator:VERSION  (K8s operator only)
make build-cli                 # host admin binary

# Standalone (containerd)
nerdctl run -d --name knxvault -p 8200:8200 … knxvault:0.4.5 serve
export KNXVAULT_ADDR=http://127.0.0.1:8200
./bin/knxvault-cli sys unseal "$UNSEAL"

# Kubernetes
# push images → set image: → kubectl apply → port-forward → knxvault-cli unseal/doctor
```
