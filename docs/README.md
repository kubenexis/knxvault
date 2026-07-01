# KNXVault Documentation

Version-controlled documentation for architects, operators, developers, and integrators. The [Low-Level Design (LLD)](lld.md) remains the authoritative technical specification; this index organizes companion guides by audience.

## Architecture & design

| Document | Audience | Description |
|----------|----------|-------------|
| [High-Level Design](architecture/hld.md) | Architects | Goals, scope, component overview |
| [Low-Level Design](lld.md) | Engineers | Full technical specification (§1–12) |
| [System diagrams](architecture/diagrams.md) | Architects | Mermaid architecture and data-flow views |
| [Data models](architecture/data-models.md) | Engineers | Domain entities and Raft persistence |
| [Security model](architecture/security-model.md) | Security / SRE | Threat model, crypto, auth, audit |
| [Envelope encryption](architecture/envelope-encryption.md) | Engineers / Security | AES-GCM envelope, DEKs, nonces, master key rotation |
| [Dragonboat storage](storage/dragonboat.md) | Engineers | Raft topology, command catalog, snapshots |
| [Raft HA & recovery](storage/raft-ha-and-recovery.md) | Engineers / SRE | Snapshots, quorum, membership, DR, partitions |
| [Phase 4 design](design/phase4-ecosystem.md) | Engineers | Ecosystem roadmap and wave breakdown |
| [ADRs](adr/README.md) | Engineers | Architecture decision records |

## Installation & configuration

| Document | Audience | Description |
|----------|----------|-------------|
| [Installation guide](installation/install.md) | Operators | Binary, Docker, Kubernetes quick start |
| [Configuration reference](installation/configuration.md) | Operators | `/etc/knxvault.conf`, environment variables, and tuning |

## Deployment & integration

| Document | Audience | Description |
|----------|----------|-------------|
| [Kubernetes deployment](deploy/kubernetes.md) | Operators | 3-node Raft StatefulSet manifests |
| [Backup & restore](deploy/backup-restore.md) | Operators | Encrypted snapshots and migration |
| [Secrets injection](deploy/secrets-injection.md) | Integrators | **CSI Driver (primary)**, sidecar/init fallbacks |
| [CSI install runbook](deploy/csi-install.md) | Operators | Production CSI driver + provider setup |
| [Kubernetes-native integrations](integration/kubernetes-native.md) | Architects | CSI, ESO, cert-manager, webhook, SDKs matrix |
| [Database credentials](deploy/database-credentials.md) | Operators | Generator-only mode, admin cred patterns |
| [Integration overview](integration/overview.md) | Integrators | K8s auth, CI/CD, client SDK patterns |

## Operations

| Document | Audience | Description |
|----------|----------|-------------|
| [Day-2 operations](operations/day2.md) | Operators | Renewal, rotation, monitoring, upgrades |
| [PKI administration](operations/pki-administration.md) | Operators | CA hierarchy, issuance recipes, renewal, CRL/OCSP |
| [PKI Kubernetes integration](operations/pki-kubernetes.md) | Operators | Ingress TLS, cert-manager, CronJob issuance patterns |
| [PKI security best practices](operations/pki-security-practices.md) | Security / SRE | Trust hierarchy, key handling, access control |
| [Operator security](operations/operator-security.md) | Operators | Credential placement, audit rules, storage classification |
| [Runbook: CA compromise](operations/runbooks/ca-compromise.md) | SRE | CA key compromise recovery |
| [Runbook: Raft failover](operations/runbooks/raft-failover.md) | SRE | Leader loss, quorum loss, recovery |
| [Runbook: Scaling](operations/runbooks/scaling.md) | SRE | Horizontal scaling and capacity |

## Observability

| Document | Audience | Description |
|----------|----------|-------------|
| [Prometheus metrics](metrics.md) | SRE | Metric catalog and scrape config |
| [Distributed tracing](observability/tracing.md) | SRE | OpenTelemetry setup |
| [Audit forwarding](observability/audit-forwarding.md) | SRE | SIEM HTTP sink configuration |

## User & API reference

| Document | Audience | Description |
|----------|----------|-------------|
| [Getting started](user/getting-started.md) | Users | Core concepts and first workflows |
| [CLI reference](cli/reference.md) | Users / operators | `knxvault-cli` commands |
| [API reference](api/reference.md) | Integrators | REST endpoints and error codes |
| [OpenAPI spec](../api/openapi.yaml) | Integrators | Machine-readable API (also at `/openapi.yaml`) |

## Engineering

| Document | Audience | Description |
|----------|----------|-------------|
| [Development guide](engineering/development.md) | Contributors | Local setup, `make` targets, layout |
| [Testing guide](engineering/testing.md) | Contributors | Unit, integration, and Raft tests |
| [Contributing](engineering/contributing.md) | Contributors | PR workflow, licenses, code standards |
| [Licensing policy](licensing.md) | Contributors | SPDX allow-list and exceptions |
| [Backlog](backlog.md) | Maintainers | Phased work items (W1–W29 complete) |
| [LLD alignment matrix](product/lld-alignment.md) | Maintainers | LLD § → code traceability |
| [Secrets manager checklist](product/secrets-manager-checklist.md) | Architects | Capability matrix vs evaluation criteria |
| [BFSI POC traceability matrix](product/bfsi-poc-traceability.md) | Architects / prospects | BFSI must-have requirements → evidence, gaps, waivers |

## Quick links

- **Swagger UI:** `http://<host>:8200/swagger` after starting the server
- **Grafana dashboard:** [`deployments/grafana/knxvault-overview.json`](../deployments/grafana/knxvault-overview.json)
- **K8s manifests:** [`deployments/k8s/`](../deployments/k8s/)