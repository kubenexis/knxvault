# KNXVault Recipes

Step-by-step guides for common tasks. Each recipe is self-contained: prerequisites, concepts, commands, verification, and troubleshooting.

| Field | Value |
|-------|-------|
| **Audience** | Operators, integrators, application teams |
| **Format** | One topic per file — copy-paste friendly |
| **Complements** | [Getting started](../user/getting-started.md), [API reference](../api/reference.md), [Manual testing strategy](../engineering/manual-testing-strategy.md) |

---

## Learning paths

### Path A — First production cluster (start here)

1. [Deploy a 3-node cluster](deploy-3-node-cluster.md)
2. [KV secrets lifecycle](kv-secrets-lifecycle.md)
3. [RBAC policies and roles](rbac-policies.md)
4. [Kubernetes ServiceAccount authentication](kubernetes-serviceaccount-auth.md)
5. [CSI driver integration](csi-driver-integration.md)

### Path B — Security and compliance

1. [Kubernetes auth security model](kubernetes-auth-security.md)
2. [OIDC authentication](oidc-authentication.md)
3. [RBAC policies and roles](rbac-policies.md)
4. [Audit export](audit-export.md)
5. [Audit SIEM forwarding](audit-siem-forwarding.md)

### Path C — High availability and operations

1. [Deploy a 3-node cluster](deploy-3-node-cluster.md)
2. [Backup and restore](backup-and-restore.md)
3. [Master key rotation](master-key-rotation.md)
4. [Seal and unseal](seal-and-unseal.md) — including multi-share ceremony
5. [Add and remove Raft nodes](raft-add-remove-node.md)
6. [Raft failover recovery](raft-failover-recovery.md)
7. [Rolling upgrade](rolling-upgrade-ha.md)

### Path D — Dynamic secrets and integrations

1. [Dynamic PostgreSQL credentials](dynamic-postgres-credentials.md)
2. [Dynamic SSH credentials](dynamic-ssh-credentials.md)
3. [Secret rotation](secret-rotation.md)
4. [Orchestrated rotation](orchestrated-rotation.md)
5. [External Secrets Operator](external-secrets-operator.md)
6. [cert-manager TLS integration](cert-manager-integration.md)

---

## Recipe index

### Cluster and storage

| Recipe | Summary |
|--------|---------|
| [Local dev single-node](local-dev-single-node.md) | Fast laptop setup without Kubernetes |
| [Deploy 3-node cluster](deploy-3-node-cluster.md) | Production HA StatefulSet + Dragonboat Raft |
| [KV secrets lifecycle](kv-secrets-lifecycle.md) | Store, update, version, list, delete, destroy |
| [Master key rotation](master-key-rotation.md) | Rotate envelope key without data loss |
| [Backup and restore](backup-and-restore.md) | Encrypted snapshots and disaster recovery |
| [Add and remove Raft nodes](raft-add-remove-node.md) | Membership changes on a running cluster |
| [Raft failover recovery](raft-failover-recovery.md) | Leader loss, quorum, and recovery |
| [Seal and unseal](seal-and-unseal.md) | Emergency seal; single-key + Shamir multi-share unseal; lab E2E coverage |
| [Rolling upgrade](rolling-upgrade-ha.md) | Upgrade image without losing quorum |

### Authentication and access control

| Recipe | Summary |
|--------|---------|
| [Kubernetes ServiceAccount auth](kubernetes-serviceaccount-auth.md) | Create SA, role, and login from a pod |
| [Kubernetes auth security](kubernetes-auth-security.md) | Why TokenReview + bindings protect KNXVault |
| [OIDC authentication](oidc-authentication.md) | Corporate IdP JWT login |
| [RBAC policies and roles](rbac-policies.md) | Policies, roles, capabilities, least privilege |
| [Token lifecycle](token-lifecycle.md) | Create, renew, and revoke client tokens |

### Audit and observability

| Recipe | Summary |
|--------|---------|
| [Audit export](audit-export.md) | Tamper-evident hash chain export and verify |
| [Audit SIEM forwarding](audit-siem-forwarding.md) | Stream events to Splunk, Loki, Elastic |

### Kubernetes integrations

| Recipe | Summary |
|--------|---------|
| [CSI driver integration](csi-driver-integration.md) | Mount KV secrets as pod volumes |
| [Mutating webhook injection](mutating-webhook-csi-injection.md) | Annotation-based CSI volume injection |
| [External Secrets Operator](external-secrets-operator.md) | Sync KV to native Kubernetes Secrets |
| [cert-manager integration](cert-manager-integration.md) | Optional Vault product profile (`/v1/*`) for legacy cert-manager |
| [Replace cert-manager (operator)](../operations/pki-replace-cert-manager.md) | **Preferred** TLS automation via CRDs |

### Secret engines

| Recipe | Summary |
|--------|---------|
| [Secret rotation](secret-rotation.md) | KV rotation schedules and CSI refresh |
| [Orchestrated rotation](orchestrated-rotation.md) | `POST /sys/rotation/run` across engines |
| [Dynamic PostgreSQL credentials](dynamic-postgres-credentials.md) | Ephemeral DB users (client and managed mode) |
| [Dynamic SSH credentials](dynamic-ssh-credentials.md) | Signed SSH user certificates |
| [PKI issue and revoke](pki-issue-and-revoke.md) | Root CA, leaf certs, CRL |

---

## Conventions used in every recipe

| Convention | Meaning |
|------------|---------|
| `$KNXVAULT_ADDR` | API base URL (e.g. `http://knxvault.knxvault.svc.cluster.local:8200`) |
| `$KNXVAULT_TOKEN` | Admin or scoped bearer token |
| `knxvault-cli` | Operator CLI (`make build-cli` or release binary) |
| **Verify** | Commands that confirm success |
| **Troubleshooting** | Common failures and fixes |

Generate a strong master key before any production recipe:

```bash
openssl rand -base64 32
```

---

## Related documentation

- [Dummies guide](../user/dummies-guide.md) — concepts and Kubernetes use cases (start here if you are new)
- [Kubernetes deployment](../deploy/kubernetes.md)
- [Configuration reference](../installation/configuration.md)
- [Security model](../architecture/security-model.md)
- [Dragonboat storage](../storage/dragonboat.md)