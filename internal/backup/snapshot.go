// Package backup exports and restores encrypted KNXVault state snapshots.
package backup

import (
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/audit"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
)

const formatVersion = 1

// Snapshot is a portable JSON representation of vault state.
type Snapshot struct {
	Version   int                  `json:"version"`
	CreatedAt time.Time            `json:"created_at"`
	CAs       []CARecord           `json:"cas"`
	Secrets   []SecretRecord       `json:"secrets"`
	Revoked   []RevokedRecord      `json:"revoked"`
	Policies  []PolicyRecord       `json:"policies"`
	Roles     []RoleRecord         `json:"roles"`
	DBRoles   []DatabaseRoleRecord `json:"database_roles"`
	Leases    []LeaseRecord        `json:"leases"`
	Issued    []IssuedCertRecord   `json:"issued_certificates"`
	Audit     []AuditRecord        `json:"audit,omitempty"`
}

// CARecord serializes a certificate authority.
type CARecord struct {
	ID            uuid.UUID    `json:"id"`
	ParentID      *uuid.UUID   `json:"parent_id,omitempty"`
	Name          string       `json:"name"`
	Type          pki.CAType   `json:"type"`
	CommonName    string       `json:"common_name"`
	Serial        string       `json:"serial"`
	CertPEM       string       `json:"cert_pem"`
	PrivateKeyEnc []byte       `json:"private_key_enc"`
	DEKEnc        []byte       `json:"dek_enc"`
	Status        pki.CAStatus `json:"status"`
	CreatedAt     time.Time    `json:"created_at"`
	ExpiresAt     time.Time    `json:"expires_at"`
	CRLNextUpdate *time.Time   `json:"crl_next_update,omitempty"`
}

// SecretRecord serializes a secret version.
type SecretRecord struct {
	ID         uuid.UUID  `json:"id"`
	Path       string     `json:"path"`
	Version    int        `json:"version"`
	DataEnc    []byte     `json:"data_enc"`
	DEKEnc     []byte     `json:"dek_enc"`
	LeaseID    *string    `json:"lease_id,omitempty"`
	TTLSeconds *int       `json:"ttl_seconds,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Destroyed  bool       `json:"destroyed"`
}

// RevokedRecord serializes a revoked certificate.
type RevokedRecord struct {
	Serial    string    `json:"serial"`
	CAID      uuid.UUID `json:"ca_id"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason"`
}

// PolicyRecord serializes an RBAC policy.
type PolicyRecord struct {
	Name       string            `json:"name"`
	Effect     domainauth.Effect `json:"effect"`
	Resources  []string          `json:"resources"`
	Actions    []string          `json:"actions"`
	Conditions map[string]any    `json:"conditions,omitempty"`
}

// RoleRecord serializes an RBAC role binding.
type RoleRecord struct {
	Name     string   `json:"name"`
	Policies []string `json:"policies"`
}

// DatabaseRoleRecord serializes a database credential role.
type DatabaseRoleRecord struct {
	Name                 string         `json:"name"`
	TTLSeconds           int            `json:"ttl_seconds"`
	UsernamePrefix       string         `json:"username_prefix"`
	DefaultUsername      string         `json:"default_username,omitempty"`
	CreationStatements   []string       `json:"creation_statements"`
	RevocationStatements []string       `json:"revocation_statements"`
	ExecutionMode        string         `json:"execution_mode,omitempty"`
	AdminCredentialsPath string         `json:"admin_credentials_path,omitempty"`
	Config               map[string]any `json:"config,omitempty"`
}

// LeaseRecord serializes a dynamic secret lease.
type LeaseRecord struct {
	ID         string     `json:"id"`
	Path       string     `json:"path"`
	RoleName   string     `json:"role_name"`
	Engine     string     `json:"engine"`
	TTLSeconds int        `json:"ttl_seconds"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Renewable  bool       `json:"renewable"`
}

// IssuedCertRecord serializes issued certificate metadata.
type IssuedCertRecord struct {
	ID                uuid.UUID `json:"id"`
	CAID              uuid.UUID `json:"ca_id"`
	Role              string    `json:"role"`
	Serial            string    `json:"serial"`
	CommonName        string    `json:"common_name"`
	DNSNames          []string  `json:"dns_names"`
	TTLSeconds        int       `json:"ttl_seconds"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	AutoRenew         bool      `json:"auto_renew"`
	RenewedFromSerial *string   `json:"renewed_from_serial,omitempty"`
}

// AuditRecord serializes an audit log entry for archival export.
type AuditRecord struct {
	Timestamp time.Time      `json:"timestamp"`
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Status    string         `json:"status"`
	Details   map[string]any `json:"details,omitempty"`
	Hash      string         `json:"hash"`
}

// Repos groups repositories used for export and restore.
type Repos struct {
	CA         repository.CARepository
	Secret     repository.SecretRepository
	Audit      repository.AuditRepository
	Revoke     repository.RevocationRepository
	Lease      repository.LeaseRepository
	Policy     repository.PolicyRepository
	Role       repository.RoleRepository
	DBRole     repository.DatabaseRoleRepository
	IssuedCert repository.IssuedCertRepository
}

func caFromDomain(ca *pki.CA) CARecord {
	return CARecord{
		ID:            ca.ID,
		ParentID:      ca.ParentID,
		Name:          ca.Name,
		Type:          ca.Type,
		CommonName:    ca.Subject.CommonName,
		Serial:        ca.Serial,
		CertPEM:       ca.CertPEM,
		PrivateKeyEnc: ca.PrivateKeyEnc,
		DEKEnc:        ca.DEKEnc,
		Status:        ca.Status,
		CreatedAt:     ca.CreatedAt,
		ExpiresAt:     ca.ExpiresAt,
		CRLNextUpdate: ca.CRLNextUpdate,
	}
}

func caToDomain(rec CARecord) *pki.CA {
	return &pki.CA{
		ID:            rec.ID,
		ParentID:      rec.ParentID,
		Name:          rec.Name,
		Type:          rec.Type,
		Subject:       pki.DistinguishedName{CommonName: rec.CommonName},
		Serial:        rec.Serial,
		CertPEM:       rec.CertPEM,
		PrivateKeyEnc: rec.PrivateKeyEnc,
		DEKEnc:        rec.DEKEnc,
		Status:        rec.Status,
		CreatedAt:     rec.CreatedAt,
		ExpiresAt:     rec.ExpiresAt,
		CRLNextUpdate: rec.CRLNextUpdate,
	}
}

func secretFromDomain(sv *secrets.SecretVersion) SecretRecord {
	return SecretRecord{
		ID:         sv.ID,
		Path:       sv.Path,
		Version:    sv.Version,
		DataEnc:    sv.DataEnc,
		DEKEnc:     sv.DEKEnc,
		LeaseID:    sv.LeaseID,
		TTLSeconds: sv.TTLSeconds,
		CreatedAt:  sv.CreatedAt,
		ExpiresAt:  sv.ExpiresAt,
		Destroyed:  sv.Destroyed,
	}
}

func secretToDomain(rec SecretRecord) *secrets.SecretVersion {
	return &secrets.SecretVersion{
		ID:         rec.ID,
		Path:       rec.Path,
		Version:    rec.Version,
		DataEnc:    rec.DataEnc,
		DEKEnc:     rec.DEKEnc,
		LeaseID:    rec.LeaseID,
		TTLSeconds: rec.TTLSeconds,
		CreatedAt:  rec.CreatedAt,
		ExpiresAt:  rec.ExpiresAt,
		Destroyed:  rec.Destroyed,
	}
}

func auditFromDomain(entry *audit.Entry) AuditRecord {
	return AuditRecord{
		Timestamp: entry.Timestamp,
		Actor:     entry.Actor,
		Action:    entry.Action,
		Resource:  entry.Resource,
		Status:    entry.Status,
		Details:   entry.Details,
		Hash:      entry.Hash,
	}
}

func auditToDomain(rec AuditRecord) *audit.Entry {
	return &audit.Entry{
		Timestamp: rec.Timestamp,
		Actor:     rec.Actor,
		Action:    rec.Action,
		Resource:  rec.Resource,
		Status:    rec.Status,
		Details:   rec.Details,
		Hash:      rec.Hash,
	}
}
