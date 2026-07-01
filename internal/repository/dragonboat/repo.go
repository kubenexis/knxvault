// Package dragonboat provides repository adapters over the vault Raft client.
package dragonboat

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/audit"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/raft"
	"github.com/kubenexis/knxvault/internal/repository"
)

type raftClient interface {
	Propose(ctx context.Context, op string, payload any) ([]byte, error)
	Read(ctx context.Context, op string, payload any) ([]byte, error)
}

func write(ctx context.Context, c raftClient, op string, payload any) error {
	data, err := c.Propose(ctx, op, payload)
	if err != nil {
		return err
	}
	return raft.DecodeResult(data, nil)
}

func read(ctx context.Context, c raftClient, op string, payload any, out any) error {
	data, err := c.Read(ctx, op, payload)
	if err != nil {
		return err
	}
	return raft.DecodeResult(data, out)
}

// Repos wires all Dragonboat-backed repositories.
type Repos struct {
	CA              *CARepository
	Secret          *SecretRepository
	Audit           *AuditRepository
	Revoke          *RevocationRepository
	Lease           *LeaseRepository
	Policy          *PolicyRepository
	Role            *RoleRepository
	DBRole          *DatabaseRoleRepository
	SSHRole         *SSHRoleRepository
	IssuedCert      *IssuedCertRepository
	PKIRole         *PKIRoleRepository
	Token           *TokenRepository
	MachineIdentity *MachineIdentityRepository
	RotationPolicy  *RotationPolicyRepository
}

// NewRepos constructs Raft repository adapters.
func NewRepos(client raftClient) Repos {
	return Repos{
		CA:              NewCARepository(client),
		Secret:          NewSecretRepository(client),
		Audit:           NewAuditRepository(client),
		Revoke:          NewRevocationRepository(client),
		Lease:           NewLeaseRepository(client),
		Policy:          NewPolicyRepository(client),
		Role:            NewRoleRepository(client),
		DBRole:          NewDatabaseRoleRepository(client),
		SSHRole:         NewSSHRoleRepository(client),
		IssuedCert:      NewIssuedCertRepository(client),
		PKIRole:         NewPKIRoleRepository(client),
		Token:           NewTokenRepository(client),
		MachineIdentity: NewMachineIdentityRepository(client),
		RotationPolicy:  NewRotationPolicyRepository(client),
	}
}

// CARepository persists certificate authorities via Raft.
type CARepository struct{ c raftClient }

func NewCARepository(c raftClient) *CARepository { return &CARepository{c: c} }

func (r *CARepository) Save(ctx context.Context, ca *pki.CA) error {
	return write(ctx, r.c, raft.OpCASave, ca)
}

func (r *CARepository) GetByID(ctx context.Context, id uuid.UUID) (*pki.CA, error) {
	var out pki.CA
	err := read(ctx, r.c, raft.OpCAGetByID, struct{ ID uuid.UUID }{ID: id}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *CARepository) GetByName(ctx context.Context, name string) (*pki.CA, error) {
	var out pki.CA
	err := read(ctx, r.c, raft.OpCAGetByName, struct{ Name string }{Name: name}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *CARepository) List(ctx context.Context) ([]*pki.CA, error) {
	var out []*pki.CA
	if err := read(ctx, r.c, raft.OpCAList, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SecretRepository persists versioned secrets via Raft.
type SecretRepository struct{ c raftClient }

func NewSecretRepository(c raftClient) *SecretRepository { return &SecretRepository{c: c} }

func (r *SecretRepository) SaveVersion(ctx context.Context, sv *secrets.SecretVersion) error {
	return write(ctx, r.c, raft.OpSecretSaveVersion, sv)
}

func (r *SecretRepository) UpdateDEKEnc(ctx context.Context, path string, version int, dekEnc []byte) error {
	return write(ctx, r.c, raft.OpSecretUpdateDEKEnc, struct {
		Path    string
		Version int
		DEKEnc  []byte
	}{Path: path, Version: version, DEKEnc: dekEnc})
}

func (r *SecretRepository) GetLatest(ctx context.Context, path string) (*secrets.SecretVersion, error) {
	var out secrets.SecretVersion
	err := read(ctx, r.c, raft.OpSecretGetLatest, struct{ Path string }{Path: path}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *SecretRepository) GetVersion(ctx context.Context, path string, version int) (*secrets.SecretVersion, error) {
	var out secrets.SecretVersion
	err := read(ctx, r.c, raft.OpSecretGetVersion, struct {
		Path    string
		Version int
	}{Path: path, Version: version}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *SecretRepository) ListByPath(ctx context.Context, pathPrefix string) ([]*secrets.SecretVersion, error) {
	var out []*secrets.SecretVersion
	err := read(ctx, r.c, raft.OpSecretListByPath, struct{ Prefix string }{Prefix: pathPrefix}, &out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *SecretRepository) NextVersion(ctx context.Context, path string) (int, error) {
	var out int
	err := read(ctx, r.c, raft.OpSecretNextVersion, struct{ Path string }{Path: path}, &out)
	return out, err
}

func (r *SecretRepository) PutAtomic(ctx context.Context, sv *secrets.SecretVersion, casVersion *int, maxVersions int) (int, error) {
	var out int
	data, err := r.c.Propose(ctx, raft.OpSecretPut, struct {
		SecretVersion secrets.SecretVersion
		CasVersion    *int
		MaxVersions   int
	}{
		SecretVersion: *sv,
		CasVersion:    casVersion,
		MaxVersions:   maxVersions,
	})
	if err != nil {
		return 0, err
	}
	if err := raft.DecodeResult(data, &out); err != nil {
		return 0, err
	}
	return out, nil
}

func (r *SecretRepository) DestroyVersion(ctx context.Context, path string, version int) error {
	return write(ctx, r.c, raft.OpSecretDestroyVer, struct {
		Path    string
		Version int
	}{Path: path, Version: version})
}

// PKIRoleRepository persists PKI roles via Raft.
type PKIRoleRepository struct{ c raftClient }

func NewPKIRoleRepository(c raftClient) *PKIRoleRepository { return &PKIRoleRepository{c: c} }

func (r *PKIRoleRepository) Save(ctx context.Context, role *pki.Role) error {
	return write(ctx, r.c, raft.OpPKIRoleSave, role)
}

func (r *PKIRoleRepository) Get(ctx context.Context, name string) (*pki.Role, error) {
	var out pki.Role
	err := read(ctx, r.c, raft.OpPKIRoleGet, struct{ Name string }{Name: name}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *PKIRoleRepository) List(ctx context.Context) ([]*pki.Role, error) {
	var out []*pki.Role
	if err := read(ctx, r.c, raft.OpPKIRoleList, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AuditRepository appends audit records via Raft.
type AuditRepository struct{ c raftClient }

func NewAuditRepository(c raftClient) *AuditRepository { return &AuditRepository{c: c} }

func (r *AuditRepository) Append(ctx context.Context, entry *audit.Entry) error {
	return write(ctx, r.c, raft.OpAuditAppend, entry)
}

func (r *AuditRepository) List(ctx context.Context, opts repository.AuditListOptions) ([]*audit.Entry, error) {
	var out []*audit.Entry
	err := read(ctx, r.c, raft.OpAuditList, opts, &out)
	return out, err
}

func (r *AuditRepository) LatestHash(ctx context.Context) (string, error) {
	var out string
	err := read(ctx, r.c, raft.OpAuditLatestHash, nil, &out)
	return out, err
}

// RevocationRepository tracks revocations via Raft.
type RevocationRepository struct{ c raftClient }

func NewRevocationRepository(c raftClient) *RevocationRepository {
	return &RevocationRepository{c: c}
}

func (r *RevocationRepository) Revoke(ctx context.Context, cert *repository.RevokedCertificate) error {
	return write(ctx, r.c, raft.OpRevoke, cert)
}

func (r *RevocationRepository) IsRevoked(ctx context.Context, serial string) (bool, error) {
	var out bool
	err := read(ctx, r.c, raft.OpRevokeIs, struct{ Serial string }{Serial: serial}, &out)
	return out, err
}

func (r *RevocationRepository) ListByCA(ctx context.Context, caID uuid.UUID) ([]*repository.RevokedCertificate, error) {
	var out []*repository.RevokedCertificate
	err := read(ctx, r.c, raft.OpRevokeListByCA, struct{ CAID uuid.UUID }{CAID: caID}, &out)
	return out, err
}

// LeaseRepository persists leases via Raft.
type LeaseRepository struct{ c raftClient }

func NewLeaseRepository(c raftClient) *LeaseRepository { return &LeaseRepository{c: c} }

func (r *LeaseRepository) Save(ctx context.Context, lease *secrets.Lease) error {
	return write(ctx, r.c, raft.OpLeaseSave, lease)
}

func (r *LeaseRepository) Get(ctx context.Context, id string) (*secrets.Lease, error) {
	var out secrets.Lease
	err := read(ctx, r.c, raft.OpLeaseGet, struct{ ID string }{ID: id}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *LeaseRepository) List(ctx context.Context) ([]*secrets.Lease, error) {
	var out []*secrets.Lease
	err := read(ctx, r.c, raft.OpLeaseList, nil, &out)
	return out, err
}

func (r *LeaseRepository) ListExpired(ctx context.Context, before time.Time, limit int) ([]*secrets.Lease, error) {
	var out []*secrets.Lease
	err := read(ctx, r.c, raft.OpLeaseListExpired, struct {
		Before time.Time
		Limit  int
	}{Before: before, Limit: limit}, &out)
	return out, err
}

func (r *LeaseRepository) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
	return write(ctx, r.c, raft.OpLeaseRevoke, struct {
		ID        string
		RevokedAt time.Time
	}{ID: id, RevokedAt: revokedAt})
}

func (r *LeaseRepository) CountActive(ctx context.Context) (int, error) {
	var count int
	err := read(ctx, r.c, raft.OpLeaseCountActive, nil, &count)
	return count, err
}

// PolicyRepository persists policies via Raft.
type PolicyRepository struct{ c raftClient }

func NewPolicyRepository(c raftClient) *PolicyRepository { return &PolicyRepository{c: c} }

func (r *PolicyRepository) Save(ctx context.Context, policy *domainauth.Policy) error {
	return write(ctx, r.c, raft.OpPolicySave, policy)
}

func (r *PolicyRepository) GetByName(ctx context.Context, name string) (*domainauth.Policy, error) {
	var out domainauth.Policy
	err := read(ctx, r.c, raft.OpPolicyGet, struct{ Name string }{Name: name}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *PolicyRepository) List(ctx context.Context) ([]*domainauth.Policy, error) {
	var out []*domainauth.Policy
	err := read(ctx, r.c, raft.OpPolicyList, nil, &out)
	return out, err
}

func (r *PolicyRepository) Delete(ctx context.Context, name string) error {
	return write(ctx, r.c, raft.OpPolicyDelete, struct{ Name string }{Name: name})
}

// RoleRepository persists roles via Raft.
type RoleRepository struct{ c raftClient }

func NewRoleRepository(c raftClient) *RoleRepository { return &RoleRepository{c: c} }

func (r *RoleRepository) Save(ctx context.Context, role *domainauth.Role) error {
	return write(ctx, r.c, raft.OpRoleSave, role)
}

func (r *RoleRepository) Get(ctx context.Context, name string) (*domainauth.Role, error) {
	var out domainauth.Role
	err := read(ctx, r.c, raft.OpRoleGet, struct{ Name string }{Name: name}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *RoleRepository) List(ctx context.Context) ([]*domainauth.Role, error) {
	var out []*domainauth.Role
	err := read(ctx, r.c, raft.OpRoleList, nil, &out)
	return out, err
}

func (r *RoleRepository) Delete(ctx context.Context, name string) error {
	return write(ctx, r.c, raft.OpRoleDelete, struct{ Name string }{Name: name})
}

// DatabaseRoleRepository persists database roles via Raft.
type DatabaseRoleRepository struct{ c raftClient }

func NewDatabaseRoleRepository(c raftClient) *DatabaseRoleRepository {
	return &DatabaseRoleRepository{c: c}
}

func (r *DatabaseRoleRepository) Save(ctx context.Context, role *secrets.DatabaseRole) error {
	return write(ctx, r.c, raft.OpDBRoleSave, role)
}

func (r *DatabaseRoleRepository) Get(ctx context.Context, name string) (*secrets.DatabaseRole, error) {
	var out secrets.DatabaseRole
	err := read(ctx, r.c, raft.OpDBRoleGet, struct{ Name string }{Name: name}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *DatabaseRoleRepository) List(ctx context.Context) ([]*secrets.DatabaseRole, error) {
	var out []*secrets.DatabaseRole
	err := read(ctx, r.c, raft.OpDBRoleList, nil, &out)
	return out, err
}

func (r *DatabaseRoleRepository) Delete(ctx context.Context, name string) error {
	return write(ctx, r.c, raft.OpDBRoleDelete, struct{ Name string }{Name: name})
}

// SSHRoleRepository persists SSH roles via Raft.
type SSHRoleRepository struct{ c raftClient }

func NewSSHRoleRepository(c raftClient) *SSHRoleRepository {
	return &SSHRoleRepository{c: c}
}

func (r *SSHRoleRepository) Save(ctx context.Context, role *secrets.SSHRole) error {
	return write(ctx, r.c, raft.OpSSHRoleSave, role)
}

func (r *SSHRoleRepository) Get(ctx context.Context, name string) (*secrets.SSHRole, error) {
	var out secrets.SSHRole
	err := read(ctx, r.c, raft.OpSSHRoleGet, struct{ Name string }{Name: name}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *SSHRoleRepository) List(ctx context.Context) ([]*secrets.SSHRole, error) {
	var out []*secrets.SSHRole
	err := read(ctx, r.c, raft.OpSSHRoleList, nil, &out)
	return out, err
}

func (r *SSHRoleRepository) Delete(ctx context.Context, name string) error {
	return write(ctx, r.c, raft.OpSSHRoleDelete, struct{ Name string }{Name: name})
}

// IssuedCertRepository tracks issued certificates via Raft.
type IssuedCertRepository struct{ c raftClient }

func NewIssuedCertRepository(c raftClient) *IssuedCertRepository {
	return &IssuedCertRepository{c: c}
}

func (r *IssuedCertRepository) Save(ctx context.Context, cert *pki.IssuedCertificate) error {
	return write(ctx, r.c, raft.OpIssuedSave, cert)
}

func (r *IssuedCertRepository) GetBySerial(ctx context.Context, caID uuid.UUID, serial string) (*pki.IssuedCertificate, error) {
	var out pki.IssuedCertificate
	err := read(ctx, r.c, raft.OpIssuedGetBySerial, struct {
		CAID   uuid.UUID
		Serial string
	}{CAID: caID, Serial: serial}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *IssuedCertRepository) List(ctx context.Context) ([]*pki.IssuedCertificate, error) {
	var out []*pki.IssuedCertificate
	err := read(ctx, r.c, raft.OpIssuedList, nil, &out)
	return out, err
}

func (r *IssuedCertRepository) ListExpiring(ctx context.Context, before time.Time, limit int) ([]*pki.IssuedCertificate, error) {
	var out []*pki.IssuedCertificate
	err := read(ctx, r.c, raft.OpIssuedListExpiring, struct {
		Before time.Time
		Limit  int
	}{Before: before, Limit: limit}, &out)
	return out, err
}

// TokenRepository persists client tokens via Raft.
type TokenRepository struct{ c raftClient }

func NewTokenRepository(c raftClient) *TokenRepository { return &TokenRepository{c: c} }

func (r *TokenRepository) Save(ctx context.Context, token *domainauth.ClientToken) error {
	return write(ctx, r.c, raft.OpTokenSave, token)
}

func (r *TokenRepository) Get(ctx context.Context, id string) (*domainauth.ClientToken, error) {
	var out domainauth.ClientToken
	err := read(ctx, r.c, raft.OpTokenGet, struct{ ID string }{ID: id}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *TokenRepository) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
	return write(ctx, r.c, raft.OpTokenRevoke, struct {
		ID        string
		RevokedAt time.Time
	}{ID: id, RevokedAt: revokedAt})
}

func (r *TokenRepository) List(ctx context.Context) ([]*domainauth.ClientToken, error) {
	var out []*domainauth.ClientToken
	err := read(ctx, r.c, raft.OpTokenList, nil, &out)
	return out, err
}

func (r *TokenRepository) ListExpired(ctx context.Context, before time.Time, limit int) ([]*domainauth.ClientToken, error) {
	var out []*domainauth.ClientToken
	err := read(ctx, r.c, raft.OpTokenListExpired, struct {
		Before time.Time
		Limit  int
	}{Before: before, Limit: limit}, &out)
	return out, err
}

// MachineIdentityRepository persists NHIs via Raft.
type MachineIdentityRepository struct{ c raftClient }

func NewMachineIdentityRepository(c raftClient) *MachineIdentityRepository {
	return &MachineIdentityRepository{c: c}
}

func (r *MachineIdentityRepository) Save(ctx context.Context, id *domainauth.MachineIdentity) error {
	return write(ctx, r.c, raft.OpMachineIdentitySave, id)
}

func (r *MachineIdentityRepository) Get(ctx context.Context, id string) (*domainauth.MachineIdentity, error) {
	var out domainauth.MachineIdentity
	err := read(ctx, r.c, raft.OpMachineIdentityGet, struct{ ID string }{ID: id}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *MachineIdentityRepository) List(ctx context.Context) ([]*domainauth.MachineIdentity, error) {
	var out []*domainauth.MachineIdentity
	err := read(ctx, r.c, raft.OpMachineIdentityList, nil, &out)
	return out, err
}

func (r *MachineIdentityRepository) Revoke(ctx context.Context, id string) error {
	return write(ctx, r.c, raft.OpMachineIdentityRevoke, struct{ ID string }{ID: id})
}

// RotationPolicyRepository persists rotation policies via Raft.
type RotationPolicyRepository struct{ c raftClient }

func NewRotationPolicyRepository(c raftClient) *RotationPolicyRepository {
	return &RotationPolicyRepository{c: c}
}

func (r *RotationPolicyRepository) Save(ctx context.Context, policy *secrets.RotationPolicy) error {
	return write(ctx, r.c, raft.OpRotationPolicySave, policy)
}

func (r *RotationPolicyRepository) Get(ctx context.Context, path string) (*secrets.RotationPolicy, error) {
	var out secrets.RotationPolicy
	err := read(ctx, r.c, raft.OpRotationPolicyGet, struct{ Path string }{Path: path}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *RotationPolicyRepository) List(ctx context.Context) ([]*secrets.RotationPolicy, error) {
	var out []*secrets.RotationPolicy
	err := read(ctx, r.c, raft.OpRotationPolicyList, nil, &out)
	return out, err
}

func (r *RotationPolicyRepository) Delete(ctx context.Context, path string) error {
	return write(ctx, r.c, raft.OpRotationPolicyDelete, struct{ Path string }{Path: path})
}
