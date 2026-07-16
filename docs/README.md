# KNXVault Documentation

Version-controlled documentation for architects, operators, developers, and integrators. The [Low-Level Design (LLD)](lld.md) remains the authoritative technical specification; this index organizes companion guides by audience.

## Architecture & design

| Document | Audience | Description |
|----------|----------|-------------|
| [High-Level Design](architecture/hld.md) | Architects | Goals, scope, operator + Vault product profile |
| [Low-Level Design](lld.md) | Engineers | Full technical specification (§1–12) |
| [System diagrams](architecture/diagrams.md) | Architects | Mermaid: layers, operator TLS, Vault profile, Raft |
| [Data models](architecture/data-models.md) | Engineers | Domain entities, PKI role resolution, operator status |
| [Security model](architecture/security-model.md) | Security / SRE | Threat model, crypto, auth (incl. AppRole), audit |
| [Envelope encryption](architecture/envelope-encryption.md) | Engineers / Security | AES-GCM envelope, DEKs, nonces, master key rotation |
| [Dragonboat storage](storage/dragonboat.md) | Engineers | Raft topology, command catalog, snapshots |
| [Raft HA & recovery](storage/raft-ha-and-recovery.md) | Engineers / SRE | Snapshots, quorum, membership, DR, partitions |
| [Phase 4–5 design](design/phase4-ecosystem.md) | Engineers | **W30 complete**; remaining ecosystem waves |
| [ADRs](adr/README.md) | Engineers | Architecture decision records |

## Installation & configuration

| Document | Audience | Description |
|----------|----------|-------------|
| [Installation guide](installation/install.md) | Operators | Binary, Docker, Kubernetes; Raft unseal; post-install verify |
| [Configuration reference](installation/configuration.md) | Operators | `/etc/knxvault.conf`, environment variables (incl. required unseal with Raft) |

## Deployment & integration

| Document | Audience | Description |
|----------|----------|-------------|
| [Kubernetes deployment](deploy/kubernetes.md) | Operators | 3-node Raft StatefulSet manifests |
| [Backup & restore](deploy/backup-restore.md) | Operators | Encrypted snapshots and migration |
| [Secrets injection](deploy/secrets-injection.md) | Integrators | **CSI Driver (primary)**, sidecar/init fallbacks |
| [CSI install runbook](deploy/csi-install.md) | Operators | Production CSI driver + provider setup |
| [Kubernetes-native integrations](integration/kubernetes-native.md) | Architects | CSI, ESO, **operator**, optional cert-manager, webhook, SDKs |
| [Database credentials](deploy/database-credentials.md) | Operators | Generator-only mode, admin cred patterns |
| [Integration overview](integration/overview.md) | Integrators | K8s auth, CI/CD, client SDK patterns |

## Operations

| Document | Audience | Description |
|----------|----------|-------------|
| [Day-2 operations](operations/day2.md) | Operators | Renewal, rotation, monitoring, upgrades |
| [PKI administration](operations/pki-administration.md) | Operators | CA hierarchy, issuance recipes, renewal, CRL/OCSP |
| [PKI Kubernetes integration](operations/pki-kubernetes.md) | Operators | Operator CRDs, Ingress TLS, optional cert-manager |
| [Replace cert-manager](operations/pki-replace-cert-manager.md) | Operators | Operator multi-issuer (Vault/ACME/SelfSigned) — no cert-manager |
| [Certificate support matrix](operations/certificate-support-matrix.md) | Architects / Operators | What replaces cert-manager (claim gate) |
| [Multi-issuer ACME design](design/multi-issuer-acme.md) | Engineers | ACME + multi-issuer architecture |
| [PKI security best practices](operations/pki-security-practices.md) | Security / SRE | Trust hierarchy, key handling, access control |
| [Operator security](operations/operator-security.md) | Operators | Credential placement, master/unseal custody, audit rules |
| [Runbook: CA compromise](operations/runbooks/ca-compromise.md) | SRE | CA key compromise recovery |
| [Runbook: Raft failover](operations/runbooks/raft-failover.md) | SRE | Leader loss, quorum loss, recovery |
| [Runbook: Scaling](operations/runbooks/scaling.md) | SRE | Horizontal scaling and capacity |

## Observability

| Document | Audience | Description |
|----------|----------|-------------|
| [Prometheus metrics](metrics.md) | SRE | Metric catalog and scrape config |
| [Distributed tracing](observability/tracing.md) | SRE | OpenTelemetry setup |
| [Audit forwarding](observability/audit-forwarding.md) | SRE | SIEM HTTP sink configuration |

## Recipes (step-by-step guides)

| Document | Audience | Description |
|----------|----------|-------------|
| [Recipes index](recipes/README.md) | Users / operators | Copy-paste guides: cluster deploy, KV, auth, CSI, dynamic secrets, audit, and more |

## User & API reference

| Document | Audience | Description |
|----------|----------|-------------|
| [Dummies guide](user/dummies-guide.md) | DevOps / platform engineers | Plain-language intro: K8s use cases, with/without KNXVault, security benefits |
| [Getting started](user/getting-started.md) | Users | Doctor, KV redaction, root/intermediate PKI, operator pointer |
| [CLI reference](cli/reference.md) | Users / operators | `knxvault-cli` commands (`doctor`, `kv get --show-secrets`) |
| [API reference](api/reference.md) | Integrators | REST endpoints and error codes |
| [OpenAPI spec](../api/openapi.yaml) | Integrators | Machine-readable API (also at `/openapi.yaml`) |

## Engineering

| Document | Audience | Description |
|----------|----------|-------------|
| [Development guide](engineering/development.md) | Contributors | Local setup, `make` targets, layout |
| [Testing guide](engineering/testing.md) | Contributors | Unit, integration, local E2E, coverage gates |
| [E2E and lab test map](engineering/e2e-and-lab-tests.md) | QA / SRE | Layers, multi-share unseal, W53 matrix, pre-release checklist |
| [Manual testing strategy](engineering/manual-testing-strategy.md) | QA / SRE | Network disruption (MT-01), rotation latency (MT-02), seal stress (MT-33) |
| [Lab full E2E](engineering/lab-full-e2e.md) | QA / SRE | **Complete** suite on 131: multi-share unseal + vaultcompat + operator (**53/53 PASS**) |
| [Lab E2E e2e-test01](engineering/lab-e2e-test01.md) | QA / SRE | Core-only **historical** smoke (20/20; superseded by lab-full-e2e) |
| [Seal and unseal recipe](recipes/seal-and-unseal.md) | Operators | Single-key + Shamir multi-share ceremony + automated coverage |
| [Contributing](engineering/contributing.md) | Contributors | PR workflow, licenses, code standards |
| [Licensing policy](licensing.md) | Contributors | SPDX allow-list and exceptions |
| [Backlog](backlog.md) | Maintainers | Phased work items; W30 operator + Vault profile **shipped** |
| [LLD alignment matrix](product/lld-alignment.md) | Maintainers | LLD § → code traceability |
| [Secrets manager checklist](product/secrets-manager-checklist.md) | Architects | Capability matrix vs evaluation criteria |
| [BFSI POC traceability matrix](product/bfsi-poc-traceability.md) | Architects / prospects | BFSI must-have requirements → evidence, gaps, waivers |

## Quick links

- **Swagger UI:** `http://<host>:8200/swagger` after starting the server
- **Grafana dashboard:** [`deployments/grafana/knxvault-overview.json`](../deployments/grafana/knxvault-overview.json)
- **K8s manifests:** [`deployments/k8s/`](../deployments/k8s/)