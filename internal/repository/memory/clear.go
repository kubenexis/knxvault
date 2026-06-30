package memory

import (
	"context"

	"github.com/google/uuid"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
)

// Clearable repositories support wiping state before a full restore.
type Clearable interface {
	Clear(context.Context) error
}

// Clear removes all CAs.
func (r *CARepository) Clear(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID = make(map[uuid.UUID]*pki.CA)
	return nil
}

// Clear removes all secret versions.
func (r *SecretRepository) Clear(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.versions = make(map[secretKey]*secrets.SecretVersion)
	return nil
}

// Clear removes all audit entries.
func (r *AuditRepository) Clear(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = nil
	r.nextID = 1
	return nil
}

// Clear removes all revocations.
func (r *RevocationRepository) Clear(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.serial = make(map[string]*repository.RevokedCertificate)
	r.byCA = make(map[uuid.UUID][]*repository.RevokedCertificate)
	return nil
}

// Clear removes all leases.
func (r *LeaseRepository) Clear(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.leases = make(map[string]*secrets.Lease)
	return nil
}

// Clear removes all policies.
func (r *PolicyRepository) Clear(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies = make(map[string]*domainauth.Policy)
	return nil
}

// Clear removes all roles.
func (r *RoleRepository) Clear(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles = make(map[string]*domainauth.Role)
	return nil
}

// Clear removes all database roles.
func (r *DatabaseRoleRepository) Clear(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles = make(map[string]*secrets.DatabaseRole)
	return nil
}

// Clear removes all issued certificate records.
func (r *IssuedCertRepository) Clear(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.certs = make(map[string]*pki.IssuedCertificate)
	return nil
}

// Clear removes all PKI roles.
func (r *PKIRoleRepository) Clear(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles = make(map[string]*pki.Role)
	return nil
}
