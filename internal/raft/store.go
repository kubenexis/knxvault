package raft

import (
	"context"
	"encoding/json"

	"github.com/kubenexis/knxvault/internal/backup"
	"github.com/kubenexis/knxvault/internal/domain/common"
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
		PKIRole:    s.PKIRole,
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
	if err := backup.ValidateSnapshot(snapshot); err != nil {
		return err
	}
	fresh := NewStore()
	if err := backup.Restore(context.Background(), fresh.Repos(), snapshot); err != nil {
		return err
	}
	*s = *fresh
	return nil
}

// Handle executes a command against the store.
func (s *Store) Handle(cmd Command) ([]byte, error) {
	handler, ok := storeHandlers[cmd.Op]
	if !ok {
		return encodeResponse(nil, common.New(common.ErrCodeValidation, "unknown raft command"))
	}
	data, err := handler(s, context.Background(), cmd.Payload)
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
