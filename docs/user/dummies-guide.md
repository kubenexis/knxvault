<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# KNXVault for Infrastructure & Kubernetes Engineers

A plain-language guide to what KNXVault is, which problems it solves in real Kubernetes environments, and how it compares to doing the same work without a dedicated secrets platform.

| Field | Value |
|-------|-------|
| **Audience** | Aspiring and early-career DevOps, SRE, and platform engineers |
| **Prerequisite knowledge** | Basic Kubernetes (Pods, Secrets, ServiceAccounts), containers, YAML |
| **Hands-on next step** | [Recipes index](../recipes/README.md) |

---

## 1. Who this guide is for

If you operate or build on Kubernetes, you will repeatedly hit the same question: **where do passwords, API keys, TLS private keys, and database credentials live — and who is allowed to read them?**

This guide is for engineers who:

- Deploy applications to Kubernetes and wonder why `Secret` objects feel awkward
- Hear “don’t commit secrets to Git” but see `.env` files and Helm values doing exactly that
- Want to understand **secrets managers** (like HashiCorp Vault) without drowning in enterprise jargon
- Are building a career in **platform engineering** — the team that makes other teams productive and secure

KNXVault is a **self-hosted secrets management and PKI system** written in Go. It gives you Vault-class patterns (central store, dynamic credentials, audit, RBAC) with a smaller footprint and **first-class Kubernetes integration** (CSI driver, ServiceAccount auth, ESO webhook, and a **native operator** that issues TLS Secrets without cert-manager).

You do not need to be a cryptographer to use it well. You do need to care about **least privilege**, **short-lived credentials**, and **traceability** — skills that distinguish strong infrastructure engineers.

---

## 2. The uncomfortable truth about secrets in Kubernetes

Kubernetes gives you a built-in `Secret` resource. Many teams treat it as “good enough.” In practice, it solves **storage in the API**, not **governance across a whole organisation**.

```
  Developer laptop                Git repo                 CI pipeline
  ┌──────────────┐               ┌──────────────┐         ┌──────────────┐
  │ .env file    │───copy───────▶│ values.yaml  │────────▶│ K8s Secret   │
  │ db_pass=xxx  │               │ password: xxx│         │ in etcd      │
  └──────────────┘               └──────────────┘         └──────┬───────┘
                                                                 │
                                                                 ▼
                                                          ┌──────────────┐
                                                          │ App Pod env  │
                                                          │ DB_PASS=xxx  │
                                                          └──────────────┘
```

### Common pain points

| Pain point | What goes wrong |
|------------|-----------------|
| **Secrets in Git** | History is forever; rotation means commits + redeploys everywhere |
| **Long-lived passwords** | DBA creates `app_user` once; same password for years across 50 pods |
| **Shared admin credentials** | Every service uses the same DB admin string “because it’s easier” |
| **No audit trail** | “Who read the production DB password Tuesday night?” — shrug |
| **Blast radius** | One leaked `Secret` or token unlocks many systems |
| **Environment drift** | Staging and prod accidentally share credentials |
| **Compliance questions** | Auditors ask for proof of access control; you have kubectl logs at best |

Platform engineers are hired to **reduce** this chaos. A secrets manager is one of the main tools for that job.

---

## 3. What is KNXVault, in one paragraph?

KNXVault is a **central control plane for secrets and certificates**. Applications and platforms ask KNXVault for what they need (a database password, an API key, a TLS cert). KNXVault:

1. **Authenticates** the caller (human, CI job, or Kubernetes ServiceAccount)
2. **Authorizes** the request against RBAC policies (can this identity read *this* path?)
3. **Returns** a secret or mints a **short-lived** credential
4. **Records** the access in a tamper-evident **audit log**
5. **Stores** sensitive payloads **encrypted** before they ever hit disk or Raft replication

It runs as a **3-node highly available cluster** on Kubernetes (Dragonboat Raft), or as a single process for local development.

KNXVault is **not** a drop-in replacement for every HashiCorp Vault plugin. It **is** a focused platform for teams that need secure KV secrets, dynamic database/SSH credentials, PKI, Kubernetes-native delivery (CSI), and operable HA — without running a large commercial stack on day one.

---

## 4. The problems KNXVault tries to solve

| # | Problem | Without a secrets manager | How KNXVault addresses it |
|---|---------|---------------------------|---------------------------|
| 1 | **Static secrets everywhere** | Passwords in Git, Helm, Slack, tickets | Central KV store; inject via CSI/files; versions and rotation |
| 2 | **Over-privileged workloads** | App pod can read all namespace Secrets | ServiceAccount → scoped token; RBAC path rules |
| 3 | **Database credential sprawl** | One shared DB user per app forever | Dynamic creds: unique user per lease, TTL, auto-revoke |
| 4 | **SSH key sharing** | Same private key on laptops and jump boxes | SSH engine: short-lived **signed certificates** |
| 5 | **TLS manual toil** | openssl commands, calendar reminders | PKI engine + **knxvault-operator** CRDs (cert-manager optional) |
| 6 | **No proof of access** | “Trust us, we’re careful” | Hash-chained audit + export + SIEM forwarding |
| 7 | **Secret leakage at rest** | etcd base64 is not encryption | Envelope encryption **before** Raft replication |
| 8 | **Single point of failure** | One VM with a `.env` file | 3-node Raft quorum, backup/restore, failover |
| 9 | **Emergency lockdown** | Revoke means hunting every copy | `sys/seal` blocks writes cluster-wide; token revoke |

---

## 5. KNXVault in your Kubernetes cluster (big picture)

```
                         ┌─────────────────────────────────────────────────────────┐
                         │                    Kubernetes cluster                      │
                         │                                                          │
   Platform engineer     │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
        │                │   │ knxvault-0  │  │ knxvault-1  │  │ knxvault-2  │   │
        │  kubectl/CLI   │   │  (Raft id=1)│  │  (Raft id=2)│  │  (Raft id=3)│   │
        └───────────────▶│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
                         │          └────────────────┼────────────────┘          │
                         │                           │ Raft quorum :63001         │
                         │                    HTTP API :8200 (Service)            │
                         │                           │                          │
                         │     ┌─────────────────────┼─────────────────────┐    │
                         │     │                     │                     │    │
                         │     ▼                     ▼                     ▼    │
                         │  ┌──────────┐      ┌──────────────┐      ┌──────────┐ │
                         │  │ knxvault │      │ knxvault-csi │      │ knxvault │ │
                         │  │ -webhook │      │  provider    │      │   -eso   │ │
                         │  └────┬─────┘      └──────┬───────┘      └────┬─────┘ │
                         │       │ inject CSI        │ mount files       │ ESO    │
                         │       │                   │                   │ sync   │
                         │       ▼                   ▼                   ▼        │
                         │  ┌─────────────────────────────────────────────────┐   │
                         │  │  Application pods (each with own ServiceAccount) │   │
                         │  │  /mnt/secrets/db.env   envFrom   native Secret  │   │
                         │  └─────────────────────────────────────────────────┘   │
                         └─────────────────────────────────────────────────────────┘
                                          │
                                          ▼
                               ┌──────────────────────┐
                               │  SIEM / audit archive │
                               │  (compliance, alerts) │
                               └──────────────────────┘
```

**Roles in this picture:**

| Component | Role |
|-----------|------|
| **KNXVault cluster** | Source of truth; encryption, policy, audit |
| **CSI provider** | Delivers secrets as **files** in the pod (preferred) |
| **Mutating webhook** | Optional: add CSI volumes from pod annotations |
| **ESO adapter** | Syncs to native `Secret` when a chart requires it |
| **knxvault-operator** | **Preferred:** CRDs → vault PKI → `kubernetes.io/tls` Secrets (no cert-manager) |
| **cert-manager** | Optional legacy: Vault issuer against KNXVault `/v1/*` profile |
| **ServiceAccount** | Pod identity for authentication — no static vault password in the image |

---

## 6. Core concepts (vocabulary cheat sheet)

| Term | Think of it as… |
|------|-----------------|
| **Path** | Folder-like name: `app/db`, `team-a/api-key` |
| **KV secret** | Versioned key-value data at a path |
| **Policy** | “May read `app/*` but not `sys/*`” |
| **Role** | Binds policies to humans, tokens, or Kubernetes ServiceAccounts |
| **Client token** | Short-lived API password after login |
| **Lease** | Timer on dynamic DB/SSH credentials |
| **Seal** | Emergency pause button for writes |
| **Raft** | Consensus protocol keeping 3 nodes in sync |
| **Envelope encryption** | Data encrypted with a random key; that key encrypted with master key |
| **Operator CRD** | Kubernetes object (`KNXVaultCertificate`) that asks KNXVault for a TLS cert |
| **Vault product profile** | Thin `/v1/*` API that looks like HashiCorp Vault for cert-manager only |

---

## 7. With vs without KNXVault — four real scenarios

### Scenario A: A microservice needs the database password

**Context:** `payments-api` in namespace `production` connects to PostgreSQL.

#### Without KNXVault

```
  ┌─────────────┐     helm upgrade      ┌─────────────────┐
  │ values.yaml │ ────────────────────▶ │ K8s Secret      │
  │ dbPassword: │                       │ payments-db     │
  │  h@rdc0ded! │                       └────────┬────────┘
  └─────────────┘                                │ envFrom
                                                 ▼
                                          ┌─────────────────┐
                                          │ payments-api    │
                                          │ DB_PASS=hard... │
                                          └─────────────────┘

  Problems:
  • Password in Git (or in CI variables duplicated from Git)
  • Same password until someone remembers to rotate
  • Any pod with Secret read in namespace can steal it
  • No central log of who fetched it
```

#### With KNXVault

```
  ┌──────────────────┐   TokenReview    ┌──────────────────┐
  │ payments-api Pod │ ───────────────▶ │ KNXVault         │
  │ SA: payments-api │ ◀─────────────── │ role: payments   │
  └────────┬─────────┘   scoped token   │ policy: read     │
           │                            │   app/payments/* │
           │ CSI mount                  └──────────────────┘
           ▼
  ┌──────────────────┐
  │ /mnt/secrets/    │
  │   db.env         │  ← file on disk, not in Helm
  └──────────────────┘

  Wins:
  • No production password in Git
  • SA-bound role: only payments-api SA in production namespace
  • Audit entry: secret.read, actor, timestamp
  • Rotate in KNXVault → CSI polling updates file (no image rebuild)
```

**Recipe:** [CSI driver integration](../recipes/csi-driver-integration.md), [Kubernetes ServiceAccount auth](../recipes/kubernetes-serviceaccount-auth.md)

---

### Scenario B: Dynamic database credentials (the “Netflix-style” pattern)

**Context:** Compliance wants **unique** DB users per workload session, revoked automatically.

#### Without KNXVault

```
  DBA runbook (manual):
  1. CREATE USER payments_svc_2024 ...
  2. Paste password into ticket
  3. Developer puts it in Secret
  4. Forget to DROP USER when app decommissioned

  ┌────────┐   shared cred    ┌────────┐
  │ App A  │ ────────────────▶│        │
  └────────┘                  │  MySQL │
  ┌────────┐   same cred       │        │
  │ App B  │ ────────────────▶│        │
  └────────┘                  └────────┘
```

#### With KNXVault

```
  App requests creds:
  POST /secrets/database/creds/readonly
           │
           ▼
  ┌─────────────────────────────────────┐
  │ KNXVault                             │
  │  username: v-k8f9a2c1                  │
  │  password: <random>                   │
  │  lease_id: abc-123                    │
  │  ttl: 3600s                           │
  │  creation_statements: CREATE USER ... │
  └─────────────────────────────────────┘
           │
           ▼ (managed mode: KNXVault runs SQL)
  PostgreSQL — user exists only until TTL / revoke

  After 1 hour (or pod exit + revoke):
  DROP USER v-k8f9a2c1
```

**Why platform engineers care:** Blast radius shrinks. A stolen credential expires. Auditors see lease issuance in the log.

**Recipe:** [Dynamic PostgreSQL credentials](../recipes/dynamic-postgres-credentials.md)

---

### Scenario C: TLS for Ingress and internal mTLS

**Context:** `shop.example.com` needs a certificate renewed before expiry.

#### Without KNXVault

```
  Engineer calendar reminder:
  ┌──────────────┐   openssl    ┌──────────────┐   kubectl    ┌─────────┐
  │ Engineer     │ ──────────▶ │ cert.pem     │ ───────────▶ │ Ingress │
  │ + USB stick? │             │ key.pem      │   create     │  TLS    │
  └──────────────┘             └──────────────┘   Secret     └─────────┘

  Risks: key on laptop, expired cert outage, no central CRL
```

#### With KNXVault (preferred: operator)

```
  knxvault-operator           KNXVault PKI
  ┌────────────────┐  issue   ┌────────────┐
  │ KNXVault       │ ────────▶│ CA + issue │
  │ Certificate CR │ ◀────────│ + renew    │
  └───────┬────────┘  leaf    └────────────┘
          │
          ▼
  kubernetes.io/tls Secret → Ingress / Pods

  Revocation: POST /pki/revoke → CRL updated
```

Optional: existing cert-manager can still use the Vault product profile (`/v1/*`).

**Recipes:** [Replace cert-manager](../operations/pki-replace-cert-manager.md), [PKI issue and revoke](../recipes/pki-issue-and-revoke.md), [cert-manager integration](../recipes/cert-manager-integration.md)

---

### Scenario D: SSH access to production (bastion / nodes)

**Context:** On-call engineers need SSH without sharing one team private key.

#### Without KNXVault

```
  #slack-oncall: "Here's the shared deploy key for the bastion 🤫"

  Everyone's laptop:
  ~/.ssh/id_deploy   ← same key, no expiry, can't revoke one person
```

#### With KNXVault

```
  Engineer or automation:
  POST /secrets/ssh/creds/ops  +  username=alice
           │
           ▼
  signed SSH certificate (valid 10 minutes)
  + ephemeral key pair

  sshd TrustedUserCAKeys → only certs signed by KNXVault CA accepted
```

**Recipe:** [Dynamic SSH credentials](../recipes/dynamic-ssh-credentials.md)

---

## 8. How authentication works (why this matters for security)

Kubernetes-native auth is the pattern you will use most often in production.

```
  Step 1: Pod starts with ServiceAccount "payments-api"
  ┌─────────────────────────────────────────┐
  │ Pod                                      │
  │  /var/run/secrets/kubernetes.io/         │
  │    serviceaccount/token  (JWT)           │
  └──────────────────┬──────────────────────┘
                     │
  Step 2: Exchange JWT for KNXVault client token
                     ▼
  ┌─────────────────────────────────────────┐
  │ KNXVault                                 │
  │  1. TokenReview → K8s API confirms JWT   │
  │  2. Match role bound_service_account_*   │
  │  3. Issue token with policies only       │
  └──────────────────┬──────────────────────┘
                     │
  Step 3: API calls with short-lived token
                     ▼
              GET /secrets/kv/app/db
              (audit logged)
```

**Without this pattern:** you embed a long-lived `KNXVAULT_TOKEN` in a Kubernetes `Secret` — which recreates the original problem (static secret in etcd).

**With this pattern:** the pod proves **identity** through Kubernetes; KNXVault proves **authorization** through RBAC. Stolen token expires. Wrong ServiceAccount gets `403`.

Deep dive: [Kubernetes auth security model](../recipes/kubernetes-auth-security.md)

---

## 9. How KNXVault improves security (the “so what?” for your career)

Interviewers and auditors care about **controls**, not buzzwords. KNXVault helps you articulate and implement them.

| Security principle | How you implement it with KNXVault |
|--------------------|-------------------------------------|
| **Least privilege** | Policies per team/path; SA-bound roles; deny `sys/*` on app roles |
| **Separation of duties** | Admins use root rarely; apps use scoped tokens only |
| **Defense in depth** | Encryption at rest + RBAC at API + K8s NetworkPolicy around vault |
| **Short-lived credentials** | DB leases, SSH certs, token TTL, CSI rotation |
| **Non-repudiation** | Audit hash chain; export for compliance; SIEM alerts |
| **Secure by default** | Encrypt-before-replicate; TokenReview fail-closed in production |
| **Recoverability** | Encrypted backups; 3-node Raft; documented failover |
| **Break-glass** | `sys/seal` during incident; master key rotation without data loss |

### What attackers get if they compromise…

| Asset compromised | Without KNXVault | With KNXVault (well configured) |
|-------------------|------------------|----------------------------------|
| Git repo | Often **all** prod secrets | Paths/metadata maybe; not vault ciphertext |
| etcd snapshot | Base64 secrets readable | App secrets not in etcd if using CSI-only delivery |
| One app pod | Namespace Secrets | Only paths allowed for that SA role |
| One DB credential | Permanent access | Lease expires; user dropped |
| Raft disk | N/A | Ciphertext only — needs master key too |

No system is magic. **You** still must protect `KNXVAULT_MASTER_KEY`, rotate bootstrap tokens, and network-segment the vault namespace. KNXVault gives you the **mechanisms** platform teams are expected to wire correctly.

---

## 10. A day in the life: platform engineer onboarding a new team

**Tuesday 09:00 — Team "Analytics" wants to deploy `etl-worker` to `production`.**

```
  Your checklist with KNXVault:

  ┌────────────────────────────────────────────────────────────────┐
  │ 1. Namespace: production                                      │
  │ 2. K8s ServiceAccount: etl-worker                             │
  │ 3. KNXVault policy: read secrets/kv/analytics/* only          │
  │ 4. KNXVault role: bind SA etl-worker @ production             │
  │ 5. Store secrets: kv put analytics/snowflake ...                │
  │ 6. SecretProviderClass + pod volume mount (CSI)               │
  │ 7. Verify: wrong SA in default namespace → 403                │
  │ 8. Document in runbook; link audit export procedure           │
  └────────────────────────────────────────────────────────────────┘
```

**Without KNXVault:** you create a generic `Secret`, paste values from a ticket, hope nobody commits `values-prod.yaml`, and answer the auditor with “we use RBAC on kubectl.”

**With KNXVault:** you deliver a **repeatable pattern** — the same recipe for every team, with audit evidence and rotation path.

---

## 11. Real-world use case matrix (Kubernetes)

| Use case | K8s touchpoints | KNXVault features | Recipe |
|----------|-----------------|-------------------|--------|
| App config (API keys, feature flags) | CSI volume, optional ESO | KVv2, RBAC, rotation | [KV lifecycle](../recipes/kv-secrets-lifecycle.md) |
| Postgres / CNPG app access | Job or managed mode | Database engine, leases | [Postgres creds](../recipes/dynamic-postgres-credentials.md) |
| Batch ETL to warehouse | CronJob SA | KV + scoped role | [K8s SA auth](../recipes/kubernetes-serviceaccount-auth.md) |
| Ingress TLS | knxvault-operator CRDs | PKI issue/renew/sign → Secret | [Replace cert-manager](../operations/pki-replace-cert-manager.md) |
| Ingress TLS (legacy) | cert-manager | Vault product profile `/v1/*` | [cert-manager](../recipes/cert-manager-integration.md) |
| GitOps without secrets in repo | CSI / ESO | Central store, version history | [CSI](../recipes/csi-driver-integration.md) |
| Human break-glass DB access | CLI + OIDC | OIDC auth, audit | [OIDC](../recipes/oidc-authentication.md) |
| On-call SSH | sshd + CA trust | SSH signed certs | [SSH creds](../recipes/dynamic-ssh-credentials.md) |
| SOC2 / ISO audit evidence | SIEM | Audit export, forwarding | [Audit export](../recipes/audit-export.md) |
| Cluster disaster | New StatefulSet | Backup restore, same master key | [Backup](../recipes/backup-and-restore.md) |
| Platform upgrade | Rolling StatefulSet | HA quorum, pre-upgrade backup | [Rolling upgrade](../recipes/rolling-upgrade-ha.md) |

---

## 12. Data flow: storing a secret (what happens under the hood)

Understanding one write path helps you debug and explain KNXVault in interviews.

```
  Client: POST /secrets/kv/app/db  { "data": { "password": "x" } }
      │
      ▼
  ┌─────────────┐
  │ Middleware  │  Auth → RBAC → Audit hook → Rate limit
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ KV engine   │  JSON serialize plaintext (in memory only)
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ Crypto      │  Random DEK → encrypt payload → wrap DEK with master key
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ Raft propose│  Only ciphertext + wrapped DEK on the wire
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ 3 replicas  │  Majority ack → durable on PVC (Pebble WAL)
  └─────────────┘

  Plaintext "x" never appears on disk or in Raft logs.
```

Read path reverses decryption **only** inside the vault process after authorization succeeds.

---

## 13. When you might *not* need KNXVault yet

Honesty builds trust. KNXVault is not mandatory for:

| Situation | Reasonable alternative |
|-----------|------------------------|
| Single developer, local prototype | `.env` + git-crypt or SOPS for one file |
| Only public config (no secrets) | ConfigMap |
| Fully managed cloud with one secret type | Cloud SM + workload identity (AWS/GCP/Azure) |
| Org already standardized on commercial Vault | Use existing investment; compare KNXVault for edge/self-hosted cases |

KNXVault shines when you run **your own Kubernetes**, need **unified** KV + dynamic DB + PKI + K8s-native delivery, and want **operable HA** without a massive platform bill.

---

## 14. Comparison snapshot: patterns engineers should know

```
  Pattern                    Complexity    Security    K8s-native
  ─────────────────────────────────────────────────────────────
  .env in repo               ▓░░░░         ★☆☆☆☆      ★☆☆☆☆
  K8s Secret only            ▓▓░░░         ★★☆☆☆      ★★★☆☆
  Sealed Secrets / SOPS      ▓▓▓░░         ★★★☆☆      ★★★☆☆
  Cloud secret manager       ▓▓▓░░         ★★★★☆      ★★★☆☆
  KNXVault (this project)    ▓▓▓▓░         ★★★★☆      ★★★★★
  Enterprise Vault cluster   ▓▓▓▓▓         ★★★★★      ★★★★☆
```

KNXVault targets the sweet spot: **strong controls**, **Kubernetes-first consumption**, **self-hosted** control plane.

---

## 15. Learning path (from zero to production-ready)

```
  Week 1 — Concepts (you are here)
      │
      ▼
  Week 2 — Local hands-on
      │   [Local dev single-node](../recipes/local-dev-single-node.md)
      │   [KV secrets lifecycle](../recipes/kv-secrets-lifecycle.md)
      │   [RBAC policies](../recipes/rbac-policies.md)
      ▼
  Week 3 — Kubernetes integration
      │   [Deploy 3-node cluster](../recipes/deploy-3-node-cluster.md)
      │   [Kubernetes SA auth](../recipes/kubernetes-serviceaccount-auth.md)
      │   [CSI driver](../recipes/csi-driver-integration.md)
      ▼
  Week 4 — Operations & security
      │   [Backup and restore](../recipes/backup-and-restore.md)
      │   [Audit export](../recipes/audit-export.md)
      │   [Master key rotation](../recipes/master-key-rotation.md)
      ▼
  Week 5 — Advanced engines
          [Dynamic Postgres](../recipes/dynamic-postgres-credentials.md)
          [Dynamic SSH](../recipes/dynamic-ssh-credentials.md)
          [Manual testing strategy](../engineering/manual-testing-strategy.md)
```

---

## 16. Glossary for interviews

| Question an interviewer might ask | Answer in KNXVault terms |
|-----------------------------------|--------------------------|
| “How do pods get secrets without etcd?” | Secrets Store CSI driver + KNXVault provider; files at mount path |
| “How do you avoid secrets in Git?” | Central KV; inject at runtime; Git holds SecretProviderClass only |
| “How do you rotate DB passwords?” | Dynamic creds with TTL or KV rotation + CSI poll |
| “How do you prove who accessed a secret?” | `GET /audit/export` hash chain + optional SIEM |
| “What if the vault node dies?” | 3-node Raft elects new leader; quorum continues |
| “What if someone steals a disk?” | Envelope encryption; need master key separately |

---

## 17. Quick reference — first commands

```bash
export KNXVAULT_ADDR=http://knxvault.knxvault.svc.cluster.local:8200
export KNXVAULT_TOKEN=<admin-token>

# Health
curl -s $KNXVAULT_ADDR/health
curl -s $KNXVAULT_ADDR/ready | jq .

# Store and read
knxvault-cli kv put app/demo value=hello
knxvault-cli kv get app/demo --show-secrets

# Policy + role (see RBAC recipe for full examples)
curl -s -X PUT $KNXVAULT_ADDR/sys/policies/demo-reader \
  -H "Authorization: Bearer $KNXVAULT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"paths":{"secrets/kv/app/*":{"capabilities":["read"]}}}'
```

---

## 18. Where to go next

| Document | Purpose |
|----------|---------|
| [Recipes index](../recipes/README.md) | Step-by-step tasks |
| [Getting started](getting-started.md) | Short hands-on tutorial |
| [Kubernetes-native integrations](../integration/kubernetes-native.md) | CSI, ESO, operator, webhook, optional cert-manager |
| [Replace cert-manager](../operations/pki-replace-cert-manager.md) | Operator-first TLS automation |
| [Security model](../architecture/security-model.md) | Threat model and controls |
| [Manual testing strategy](../engineering/manual-testing-strategy.md) | Validate before production |

---

## 19. Summary

KNXVault exists because **Kubernetes alone does not solve secrets governance**. Teams still leak credentials into Git, share long-lived passwords, and cannot answer audit questions. KNXVault centralizes secrets and certificates, encrypts them before replication, delivers them to pods through Kubernetes-native patterns, and logs access in a verifiable way.

As an infrastructure or platform engineer, your job is not to memorize every API endpoint — it is to **design flows** where applications receive exactly the credentials they need, for exactly as long as they need them, with evidence left behind. KNXVault is built to make those flows repeatable across dozens of teams and clusters.

Start with one app, one ServiceAccount, one CSI mount, and one audit export. Then expand.