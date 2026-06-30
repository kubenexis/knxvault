# Operator Security Guidance

Production checklist for KNXVault operators. Complements the [security model](../architecture/security-model.md).

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

## Bootstrap hardening checklist

- [ ] Replace bootstrap root token with scoped policies and roles
- [ ] Store `KNXVAULT_MASTER_KEY` in a sealed K8s Secret or external KMS
- [ ] Enable TLS at ingress
- [ ] Restrict `/metrics` with NetworkPolicy
- [ ] Set `KNXVAULT_AUDIT_SIGNING_KEY`
- [ ] Enable `KNXVAULT_RATE_LIMIT_ENABLED` in production
- [ ] Store admin DB credentials in KV, not in database role config
- [ ] Schedule encrypted backups (`scripts/backup.sh` or CLI)

## PKI-specific guidance

See [PKI security best practices](pki-security-practices.md) for trust hierarchy, private key handling, and issuance access control.

## Related documents

- [Security model](../architecture/security-model.md)
- [Database credentials](../deploy/database-credentials.md)
- [Day-2 operations](day2.md)
- [ADR-0004: Encrypt before replication](../adr/0004-encrypt-before-replication.md)
- [ADR-0005: Cleartext metadata in Raft](../adr/0005-cleartext-metadata-in-raft.md)