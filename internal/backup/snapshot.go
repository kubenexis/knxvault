// Package backup exports and restores encrypted KNXVault state snapshots.
package backup

import (
	"time"

	"github.com/google/uuid"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/pki"
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
	PKIRoles  []PKIRoleRecord      `json:"pki_roles,omitempty"`
	DBRoles   []DatabaseRoleRecord `json:"database_roles"`
	Leases    []LeaseRecord        `json:"leases"`
	Issued    []IssuedCertRecord   `json:"issued_certificates"`
	Audit     []AuditRecord        `json:"audit,omitempty"`
	Tokens    []TokenRecord        `json:"tokens,omitempty"`
}

// TokenRecord serializes a persisted client token.
type TokenRecord struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	Policies  []string  `json:"policies"`
	ExpiresAt time.Time `json:"expires_at"`
	Renewable bool      `json:"renewable"`
	Revoked   bool      `json:"revoked"`
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
	Name                          string   `json:"name"`
	Policies                      []string `json:"policies"`
	BoundServiceAccountNames      []string `json:"bound_service_account_names,omitempty"`
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces,omitempty"`
}

// PKIRoleRecord serializes a PKI issuance role policy.
type PKIRoleRecord struct {
	Name            string        `json:"name"`
	CAName          string        `json:"ca_name"`
	AllowedDomains  []string      `json:"allowed_domains,omitempty"`
	MaxTTLSeconds   int           `json:"max_ttl_seconds"`
	KeyUsage        pki.RoleUsage `json:"key_usage"`
	AllowSubdomains bool          `json:"allow_subdomains"`
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
	PKIRole    repository.PKIRoleRepository
	DBRole     repository.DatabaseRoleRepository
	IssuedCert repository.IssuedCertRepository
	Token      repository.TokenRepository
}
