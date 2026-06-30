// Package repository defines persistence interfaces (LLD §4.D.3).
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/audit"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

// CARepository persists certificate authorities.
type CARepository interface {
	Save(ctx context.Context, ca *pki.CA) error
	GetByID(ctx context.Context, id uuid.UUID) (*pki.CA, error)
	GetByName(ctx context.Context, name string) (*pki.CA, error)
	List(ctx context.Context) ([]*pki.CA, error)
}

// SecretRepository persists versioned secrets.
type SecretRepository interface {
	SaveVersion(ctx context.Context, sv *secrets.SecretVersion) error
	PutAtomic(ctx context.Context, sv *secrets.SecretVersion, casVersion *int, maxVersions int) (int, error)
	GetLatest(ctx context.Context, path string) (*secrets.SecretVersion, error)
	GetVersion(ctx context.Context, path string, version int) (*secrets.SecretVersion, error)
	ListByPath(ctx context.Context, pathPrefix string) ([]*secrets.SecretVersion, error)
	NextVersion(ctx context.Context, path string) (int, error)
	DestroyVersion(ctx context.Context, path string, version int) error
}

// PKIRoleRepository persists PKI issuance role policies.
type PKIRoleRepository interface {
	Save(ctx context.Context, role *pki.Role) error
	Get(ctx context.Context, name string) (*pki.Role, error)
	List(ctx context.Context) ([]*pki.Role, error)
}

// AuditListOptions filters audit log queries.
type AuditListOptions struct {
	Since    *time.Time
	Limit    int
	Offset   int
	OrderAsc bool
}

// AuditRepository appends and queries immutable audit records.
type AuditRepository interface {
	Append(ctx context.Context, entry *audit.Entry) error
	List(ctx context.Context, opts AuditListOptions) ([]*audit.Entry, error)
	LatestHash(ctx context.Context) (string, error)
}

// RevokedCertificate is a revoked leaf certificate record.
type RevokedCertificate struct {
	Serial    string
	CAID      uuid.UUID
	RevokedAt time.Time
	Reason    string
}

// RevocationRepository tracks revoked certificate serials.
type RevocationRepository interface {
	Revoke(ctx context.Context, cert *RevokedCertificate) error
	IsRevoked(ctx context.Context, serial string) (bool, error)
	ListByCA(ctx context.Context, caID uuid.UUID) ([]*RevokedCertificate, error)
}

// LeaseRepository persists dynamic secret leases.
type LeaseRepository interface {
	Save(ctx context.Context, lease *secrets.Lease) error
	Get(ctx context.Context, id string) (*secrets.Lease, error)
	List(ctx context.Context) ([]*secrets.Lease, error)
	ListExpired(ctx context.Context, before time.Time, limit int) ([]*secrets.Lease, error)
	CountActive(ctx context.Context) (int, error)
	Revoke(ctx context.Context, id string, revokedAt time.Time) error
}

// PolicyRepository persists RBAC policies.
type PolicyRepository interface {
	Save(ctx context.Context, policy *domainauth.Policy) error
	GetByName(ctx context.Context, name string) (*domainauth.Policy, error)
	List(ctx context.Context) ([]*domainauth.Policy, error)
	Delete(ctx context.Context, name string) error
}

// RoleRepository persists RBAC role bindings.
type RoleRepository interface {
	Save(ctx context.Context, role *domainauth.Role) error
	Get(ctx context.Context, name string) (*domainauth.Role, error)
	List(ctx context.Context) ([]*domainauth.Role, error)
	Delete(ctx context.Context, name string) error
}

// DatabaseRoleRepository persists database credential role configuration.
type DatabaseRoleRepository interface {
	Save(ctx context.Context, role *secrets.DatabaseRole) error
	Get(ctx context.Context, name string) (*secrets.DatabaseRole, error)
	List(ctx context.Context) ([]*secrets.DatabaseRole, error)
	Delete(ctx context.Context, name string) error
}

// IssuedCertRepository tracks issued leaf certificates for renewal.
type IssuedCertRepository interface {
	Save(ctx context.Context, cert *pki.IssuedCertificate) error
	GetBySerial(ctx context.Context, caID uuid.UUID, serial string) (*pki.IssuedCertificate, error)
	List(ctx context.Context) ([]*pki.IssuedCertificate, error)
	ListExpiring(ctx context.Context, before time.Time, limit int) ([]*pki.IssuedCertificate, error)
}
