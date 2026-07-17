<!--
Copyright The KNXVault Authors.
SPDX-License-Identifier: CC-BY-4.0
-->

# Operator Security Guidance

Production checklist for KNXVault operators. Complements the [security model](../architecture/security-model.md).

> **Day-0 + Day-2 narrative** (bring-up through first apps, then operate): [Operator runbook](operator-runbook.md).

## 1. Never put passwords in database role `config`

Database roles store **SQL templates and tuning only**. Credential material belongs elsewhere.

| Do | Don't |
|----|-------|
| Store admin DB creds in KV: `POST /secrets/kv/database/admin/prod-db` | Put `connection_url`, `password`, or `database_url` in role `config` |
| Set `admin_credentials_path: "database/admin/prod-db"` as a runbook reference | Embed `mysql://user:pass@host` anywhere in the role |
| Use `config` for `db_type`, `ssl_mode`, `database_name`, `host` (no password) | Copy bootstrap tokens into role config |

The API **rejects** credential-like keys and embedded URLs in `config`. See [Database credentials](../deploy/database-credentials.md).

### Where admin credentials live

| Pattern | Example |
|---------|---------|
| **KV path (recommended)** | `secrets/kv/database/admin/prod-db` — encrypted before Raft |
| **Kubernetes Secret** | Mounted in the job that runs `creation_statements` |
| **Passwordless admin** | RDS IAM auth, Cloud SQL IAM, cert-based MySQL auth |
| **External vault** | CI variable; executor never stores in KNXVault role config |

Full workflow: [Database credentials](../deploy/database-credentials.md).

## 2. Audit log discipline

KNXVault **strips** sensitive values from audit `details` before persistence:

- Keys like `password`, `token`, `connection_url` → `[REDACTED]`
- Strings resembling `scheme://user:pass@host` → `[REDACTED]`

**Operator rules:**

- Do not rely on redaction as a license to log secrets — avoid passing secret values in `details` from custom integrations
- Audit `resource` fields include paths (e.g. `secrets/kv/app/db`) by design for compliance traceability
- Enable `KNXVAULT_AUDIT_SIGNING_KEY` for tamper-evident exports

Implementation: `internal/audit/redact.go` (`SanitizeDetails`).

## 3. Secret path visibility (not encrypted)

Secret **paths**, versions, and TTL metadata are stored in cleartext in Raft. This is intentional:

- RBAC policies match on path prefixes (`secrets/kv/app/*`)
- Operators list and inject secrets by path
- Encrypting paths would break policy evaluation and add significant complexity

If hiding the **existence** of secrets is a hard requirement, path encryption is **not implemented** in v0.1.x — evaluate separate vault instances per classification level instead. See [ADR-0005](../adr/0005-cleartext-metadata-in-raft.md).

## 4. Intentional cleartext in Raft

The following are **not encrypted** at the storage layer by design:

| Data | Rationale |
|------|-----------|
| CA certificate PEM | Public; distributed to clients and OCSP/CRL consumers |
| RBAC policies and roles | Authorization config; no secret payloads |
| Audit log entries | Compliance readability; values redacted in `details` |
| Secret paths, lease IDs, PKI metadata | Operational routing; not secret values |

Secret **values**, CA **private keys**, and generated DB credentials are encrypted before replication ([ADR-0004](../adr/0004-encrypt-before-replication.md)).

## 5. Master key and unseal key custody

Two distinct operational secrets. Do not conflate them.

| Secret | Purpose | Raft requirement |
|--------|---------|------------------|
| `KNXVAULT_MASTER_KEY` | Envelope encryption (wraps DEKs for secrets and CA private keys) | Required for production storage |
| `KNXVAULT_UNSEAL_KEY` | Operational seal/unseal (`POST /sys/seal`, `POST /sys/unseal`) | **Required at process start** when `KNXVAULT_RAFT_ENABLED=true` |
| Shamir shares (optional) | Custodian presentation of unseal when `KNXVAULT_UNSEAL_THRESHOLD>1` | Split offline or via admin API while unsealed; process still loads full unseal secret at start |

**Rules:**

1. Generate master and unseal with high entropy: `openssl rand -base64 32`.
2. When Raft is enabled, unseal **must not equal** master. Startup fails if unseal is missing or identical to master (`unseal key is required when raft is enabled`).
3. Store both in a sealed Kubernetes Secret, sealed-secrets, or external KMS — never in ConfigMaps, Git, or chat.
4. Back up both with the same custody as the master key; losing unseal blocks recovery from a sealed state.
5. Unseal is **not** used for envelope encryption (see [envelope encryption](../architecture/envelope-encryption.md)).
6. Process **starts sealed** when an unseal key is configured. After install or restart, unseal (full key or **t-of-n shares**) before data-plane use; then `knxvault-cli doctor --json` (`server.sealed` ok, `healthy` true).
7. Multi-share: set `KNXVAULT_UNSEAL_THRESHOLD`; distribute shares with offline `go run ./scripts/shamir-split` or `POST /sys/generate-unseal-shares` (unsealed only). Lab proves start sealed → shares only → data plane ([lab-full-e2e.md](../engineering/lab-full-e2e.md)).

K8s template: [`deployments/k8s/secret.yaml`](../../deployments/k8s/secret.yaml). Recipe: [Seal and unseal](../recipes/seal-and-unseal.md). Test map: [E2E and lab tests](../engineering/e2e-and-lab-tests.md).

## Bootstrap hardening checklist

Manual checklist today. **Productization** (profile fail-closed, production kustomize, root revoke, doctor gate, KMS unseal) is tracked as **M-PRODSEC-1 / M-CUSTODY-1 / W75** — see [production security posture design](../design/production-security-posture.md), [CIS hardening](../design/cis-hardening-improvements.md), and [posture assessment](../architecture/security-posture-assessment.md).

**Production K8s install (preferred):** `kubectl apply -k deployments/k8s/production` — sets `KNXVAULT_SECURITY_PROFILE=production` and a default-deny-style NetworkPolicy. Multi-node Raft **forces** production in the binary unless lab + `KNXVAULT_RAFT_ALLOW_INSECURE=true`.

- [ ] Replace bootstrap root token with scoped policies and roles
- [ ] Store `KNXVAULT_MASTER_KEY` in a sealed K8s Secret or external KMS
- [ ] Store `KNXVAULT_UNSEAL_KEY` separately from master (required with Raft; never equal master)
- [ ] If multi-share: set `KNXVAULT_UNSEAL_THRESHOLD`, distribute offline shares, document custodian process
- [ ] Enable TLS at ingress (or server TLS); plain HTTP triggers a `doctor` warn
- [ ] Restrict `/metrics` and unauthenticated `/sys/unseal` with NetworkPolicy
- [ ] Set `KNXVAULT_AUDIT_SIGNING_KEY`
- [ ] Rate limiting is on by default (`KNXVAULT_RATE_LIMIT_ENABLED`); keep enabled in production
- [ ] Store admin DB credentials in KV, not in database role config
- [ ] Schedule encrypted backups (`scripts/backup.sh` or CLI)
- [ ] Post-deploy verify: unseal completed, `/health`/`/ready` (`sealed:false`, `raft_ready:true`), `doctor --json` (`fail:0`)
- [ ] Prefer operator **SA auth** (no root token) and restrict who can create `KNXVaultClusterIssuer`

## PKI-specific guidance

See [PKI security best practices](pki-security-practices.md) for trust hierarchy, private key handling, and issuance access control.

## Related documents

- [Security model](../architecture/security-model.md)
- [Installation guide](../installation/install.md)
- [Configuration reference](../installation/configuration.md)
- [Database credentials](../deploy/database-credentials.md)
- [Day-2 operations](day2.md)
- [ADR-0004: Encrypt before replication](../adr/0004-encrypt-before-replication.md)
- [ADR-0005: Cleartext metadata in Raft](../adr/0005-cleartext-metadata-in-raft.md)