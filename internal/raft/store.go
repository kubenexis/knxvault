package raft

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/backup"
	"github.com/kubenexis/knxvault/internal/domain/audit"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

// Store holds vault state replicated by Raft.
type Store struct {
	CA         *memory.CARepository
	Secret     *memory.SecretRepository
	Audit      *memory.AuditRepository
	Revoke     *memory.RevocationRepository
	Lease      *memory.LeaseRepository
	Policy     *memory.PolicyRepository
	Role       *memory.RoleRepository
	DBRole     *memory.DatabaseRoleRepository
	IssuedCert *memory.IssuedCertRepository
	PKIRole    *memory.PKIRoleRepository
}

// NewStore constructs an empty vault store.
func NewStore() *Store {
	return &Store{
		CA:         memory.NewCARepository(),
		Secret:     memory.NewSecretRepository(),
		Audit:      memory.NewAuditRepository(),
		Revoke:     memory.NewRevocationRepository(),
		Lease:      memory.NewLeaseRepository(),
		Policy:     memory.NewPolicyRepository(),
		Role:       memory.NewRoleRepository(),
		DBRole:     memory.NewDatabaseRoleRepository(),
		IssuedCert: memory.NewIssuedCertRepository(),
		PKIRole:    memory.NewPKIRoleRepository(),
	}
}

// Repos returns backup/export repositories backed by this store.
func (s *Store) Repos() backup.Repos {
	return backup.Repos{
		CA:         s.CA,
		Secret:     s.Secret,
		Audit:      s.Audit,
		Revoke:     s.Revoke,
		Lease:      s.Lease,
		Policy:     s.Policy,
		Role:       s.Role,
		DBRole:     s.DBRole,
		IssuedCert: s.IssuedCert,
	}
}

// ExportSnapshot builds a portable snapshot from store state.
func (s *Store) ExportSnapshot(includeAudit bool) (*backup.Snapshot, error) {
	return backup.Export(context.Background(), s.Repos(), backup.ExportOptions{IncludeAudit: includeAudit})
}

// ImportSnapshot replaces store state from a snapshot.
func (s *Store) ImportSnapshot(snapshot *backup.Snapshot) error {
	fresh := NewStore()
	if err := backup.Restore(context.Background(), fresh.Repos(), snapshot); err != nil {
		return err
	}
	*s = *fresh
	return nil
}

// Handle executes a command against the store.
func (s *Store) Handle(cmd Command) ([]byte, error) {
	ctx := context.Background()
	var (
		data any
		err  error
	)
	switch cmd.Op {
	case OpCASave:
		var ca pki.CA
		err = json.Unmarshal(cmd.Payload, &ca)
		if err == nil {
			err = s.CA.Save(ctx, &ca)
		}
	case OpCAGetByID:
		var req struct{ ID uuid.UUID }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.CA.GetByID(ctx, req.ID)
		}
	case OpCAGetByName:
		var req struct{ Name string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.CA.GetByName(ctx, req.Name)
		}
	case OpCAList:
		data, err = s.CA.List(ctx)
	case OpSecretSaveVersion:
		var sv secrets.SecretVersion
		err = json.Unmarshal(cmd.Payload, &sv)
		if err == nil {
			err = s.Secret.SaveVersion(ctx, &sv)
		}
	case OpSecretGetLatest:
		var req struct{ Path string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.Secret.GetLatest(ctx, req.Path)
		}
	case OpSecretGetVersion:
		var req struct {
			Path    string
			Version int
		}
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.Secret.GetVersion(ctx, req.Path, req.Version)
		}
	case OpSecretListByPath:
		var req struct{ Prefix string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.Secret.ListByPath(ctx, req.Prefix)
		}
	case OpSecretNextVersion:
		var req struct{ Path string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.Secret.NextVersion(ctx, req.Path)
		}
	case OpSecretPut:
		var req struct {
			SecretVersion secrets.SecretVersion
			CasVersion    *int
			MaxVersions   int
		}
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.Secret.PutAtomic(ctx, &req.SecretVersion, req.CasVersion, req.MaxVersions)
		}
	case OpSecretDestroyVer:
		var req struct {
			Path    string
			Version int
		}
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			err = s.Secret.DestroyVersion(ctx, req.Path, req.Version)
		}
	case OpPKIRoleSave:
		var role pki.Role
		err = json.Unmarshal(cmd.Payload, &role)
		if err == nil {
			err = s.PKIRole.Save(ctx, &role)
			if err == nil {
				data = role
			}
		}
	case OpPKIRoleGet:
		var req struct{ Name string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.PKIRole.Get(ctx, req.Name)
		}
	case OpPKIRoleList:
		data, err = s.PKIRole.List(ctx)
	case OpAuditAppend:
		var entry audit.Entry
		err = json.Unmarshal(cmd.Payload, &entry)
		if err == nil {
			err = s.Audit.Append(ctx, &entry)
			if err == nil {
				data = entry
			}
		}
	case OpAuditList:
		var opts repository.AuditListOptions
		err = json.Unmarshal(cmd.Payload, &opts)
		if err == nil {
			data, err = s.Audit.List(ctx, opts)
		}
	case OpAuditLatestHash:
		data, err = s.Audit.LatestHash(ctx)
	case OpRevoke:
		var cert repository.RevokedCertificate
		err = json.Unmarshal(cmd.Payload, &cert)
		if err == nil {
			err = s.Revoke.Revoke(ctx, &cert)
		}
	case OpRevokeIs:
		var req struct{ Serial string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.Revoke.IsRevoked(ctx, req.Serial)
		}
	case OpRevokeListByCA:
		var req struct{ CAID uuid.UUID }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.Revoke.ListByCA(ctx, req.CAID)
		}
	case OpLeaseSave:
		var lease secrets.Lease
		err = json.Unmarshal(cmd.Payload, &lease)
		if err == nil {
			err = s.Lease.Save(ctx, &lease)
		}
	case OpLeaseGet:
		var req struct{ ID string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.Lease.Get(ctx, req.ID)
		}
	case OpLeaseList:
		data, err = s.Lease.List(ctx)
	case OpLeaseListExpired:
		var req struct {
			Before time.Time
			Limit  int
		}
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.Lease.ListExpired(ctx, req.Before, req.Limit)
		}
	case OpLeaseRevoke:
		var req struct {
			ID        string
			RevokedAt time.Time
		}
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			err = s.Lease.Revoke(ctx, req.ID, req.RevokedAt)
		}
	case OpPolicySave:
		var policy domainauth.Policy
		err = json.Unmarshal(cmd.Payload, &policy)
		if err == nil {
			err = s.Policy.Save(ctx, &policy)
			if err == nil {
				data = policy
			}
		}
	case OpPolicyGet:
		var req struct{ Name string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.Policy.GetByName(ctx, req.Name)
		}
	case OpPolicyList:
		data, err = s.Policy.List(ctx)
	case OpPolicyDelete:
		var req struct{ Name string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			err = s.Policy.Delete(ctx, req.Name)
		}
	case OpRoleSave:
		var role domainauth.Role
		err = json.Unmarshal(cmd.Payload, &role)
		if err == nil {
			err = s.Role.Save(ctx, &role)
		}
	case OpRoleGet:
		var req struct{ Name string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.Role.Get(ctx, req.Name)
		}
	case OpRoleList:
		data, err = s.Role.List(ctx)
	case OpRoleDelete:
		var req struct{ Name string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			err = s.Role.Delete(ctx, req.Name)
		}
	case OpDBRoleSave:
		var role secrets.DatabaseRole
		err = json.Unmarshal(cmd.Payload, &role)
		if err == nil {
			err = s.DBRole.Save(ctx, &role)
		}
	case OpDBRoleGet:
		var req struct{ Name string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.DBRole.Get(ctx, req.Name)
		}
	case OpDBRoleList:
		data, err = s.DBRole.List(ctx)
	case OpDBRoleDelete:
		var req struct{ Name string }
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			err = s.DBRole.Delete(ctx, req.Name)
		}
	case OpIssuedSave:
		var cert pki.IssuedCertificate
		err = json.Unmarshal(cmd.Payload, &cert)
		if err == nil {
			err = s.IssuedCert.Save(ctx, &cert)
		}
	case OpIssuedGetBySerial:
		var req struct {
			CAID   uuid.UUID
			Serial string
		}
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.IssuedCert.GetBySerial(ctx, req.CAID, req.Serial)
		}
	case OpIssuedList:
		data, err = s.IssuedCert.List(ctx)
	case OpIssuedListExpiring:
		var req struct {
			Before time.Time
			Limit  int
		}
		err = json.Unmarshal(cmd.Payload, &req)
		if err == nil {
			data, err = s.IssuedCert.ListExpiring(ctx, req.Before, req.Limit)
		}
	case OpImportSnapshot:
		var snapshot backup.Snapshot
		err = json.Unmarshal(cmd.Payload, &snapshot)
		if err == nil {
			err = s.ImportSnapshot(&snapshot)
		}
	default:
		err = common.New(common.ErrCodeValidation, "unknown raft command")
	}
	if err != nil {
		return encodeResponse(nil, err)
	}
	return encodeResponse(data, nil)
}

// Lookup executes a read-only command.
func (s *Store) Lookup(query Command) ([]byte, error) {
	if !IsReadOnlyOp(query.Op) {
		return encodeResponse(nil, common.New(common.ErrCodeValidation, "write command not allowed on read path"))
	}
	return s.Handle(query)
}

// DecodeResult unmarshals a successful response payload.
func DecodeResult(data []byte, out any) error {
	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}
	if resp.ErrorCode != "" {
		return common.New(common.ErrorCode(resp.ErrorCode), resp.Message)
	}
	if out == nil || len(resp.Data) == 0 {
		return nil
	}
	return json.Unmarshal(resp.Data, out)
}
