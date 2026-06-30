# Data Models

Domain entities and how they persist in the Dragonboat Raft state machine. Go structs live under `internal/domain/`; Raft commands are documented in [Dragonboat storage](../storage/dragonboat.md).

## Entity relationship overview

```mermaid
erDiagram
    CA ||--o{ CA : "parent_id"
    CA ||--o{ REVOCATION : "ca_id"
    CA ||--o{ ISSUED_CERT : "ca_id"
    SECRET_VERSION }o--|| LEASE : "optional lease_id"
    POLICY ||--o{ ROLE : "policy bindings"
    DATABASE_ROLE ||--o{ LEASE : "generated creds"
    AUDIT_ENTRY ||--|| AUDIT_ENTRY : "prev_hash chain"
```

## PKI

### CA (`internal/domain/pki/ca.go`)

| Field | Type | Notes |
|-------|------|-------|
| `ID` | UUID | Primary key |
| `ParentID` | UUID? | Set for intermediate CAs |
| `Name` | string | Unique human name |
| `Type` | `root` \| `intermediate` | Hierarchy level |
| `Subject` | DistinguishedName | CN, O, OU, C |
| `Serial` | string | CA certificate serial |
| `CertPEM` | string | Public certificate |
| `PrivateKeyEnc` | bytes | Envelope-encrypted private key |
| `DEKEnc` | bytes | Master-key-wrapped DEK |
| `Status` | `active` \| `revoked` | Lifecycle |
| `ExpiresAt` | time | Not-after |
| `CRLNextUpdate` | time? | CRL scheduling hint |

**Raft ops:** `ca.save`, `ca.get_by_id`, `ca.get_by_name`, `ca.list`

### Issued certificate (`internal/domain/pki/issued_cert.go`)

Tracks leaf certificates for auto-renewal. Stores metadata only — private keys are returned to the caller at issuance time unless stored in a secret path separately.

| Field | Notes |
|-------|-------|
| `CAID`, `Serial` | Lookup keys |
| `CommonName`, `SANs` | Identity |
| `AutoRenew` | Enables background renewal job |
| `ExpiresAt` | Renewal window trigger |

**Raft ops:** `issued.save`, `issued.get_by_serial`, `issued.list`, `issued.list_expiring`

### Revocation

| Field | Notes |
|-------|-------|
| `CAID`, `Serial` | Revoked certificate |
| `RevokedAt` | Timestamp |
| `Reason` | CRL reason code |

**Raft ops:** `revoke.save`, `revoke.is`, `revoke.list_by_ca`

## Secrets

### Secret version (`internal/domain/secrets/version.go`)

| Field | Type | Notes |
|-------|------|-------|
| `Path` | string | Hierarchical path (e.g. `app/db`) |
| `Version` | int | Monotonic per path |
| `DataEnc` | bytes | AES-256-GCM ciphertext |
| `DEKEnc` | bytes | Wrapped DEK |
| `TTLSeconds` | int? | Optional expiration |
| `Destroyed` | bool | Soft-delete marker |

**Raft ops:** `secret.save_version`, `secret.get_latest`, `secret.get_version`, `secret.list_by_path`, `secret.next_version`

### Lease (`internal/domain/secrets/lease.go`)

Dynamic credential leases (database engine).

| Field | Notes |
|-------|-------|
| `ID` | Opaque lease identifier |
| `RoleName` | Database role config reference |
| `ExpiresAt` | TTL boundary |
| `Revoked` | Early termination |

**Raft ops:** `lease.save`, `lease.get`, `lease.list`, `lease.list_expired`, `lease.revoke`

### Database role (`internal/domain/secrets/database_role.go`)

Connection and credential generation configuration for dynamic DB secrets.

**Raft ops:** `db_role.save`, `db_role.get`, `db_role.list`, `db_role.delete`

## Auth & RBAC

### Policy (`internal/domain/auth/policy.go`)

HCL-like policy documents with path capabilities and optional conditions (`ip_cidr`, `time_after`, `time_before`, `path_prefix`, `namespace`).

**Raft ops:** `policy.save`, `policy.get_by_name`, `policy.list`, `policy.delete`

### Role

Maps token identities (or K8s SA bindings) to policy sets.

**Raft ops:** `role.save`, `role.get`, `role.list`, `role.delete`

## Audit

### Audit entry (`internal/domain/audit/entry.go`)

| Field | Notes |
|-------|-------|
| `Actor` | Authenticated subject |
| `Action` | Operation name |
| `Resource` | Target path or ID |
| `PrevHash` | SHA-256 chain link |
| `Hash` | Entry digest |

**Raft ops:** `audit.append`, `audit.list`, `audit.latest_hash`

Export API adds HMAC signatures when `KNXVAULT_AUDIT_SIGNING_KEY` is configured.

## Snapshot and backup format

Raft snapshots and `POST /sys/backup` share the JSON format in `internal/backup.Snapshot`:

- `format`: `knxvault-backup`
- `version`: `1`
- Encrypted payload (`ciphertext`, `dek_enc`) sealed with the master key
- Full state replacement via `snapshot.import` on restore

