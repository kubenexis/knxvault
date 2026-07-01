package raft

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/backup"
	"github.com/kubenexis/knxvault/internal/domain/audit"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
)

type storeHandler func(s *Store, ctx context.Context, payload json.RawMessage) (any, error)

var storeHandlers = map[string]storeHandler{
	OpCASave:                handleCASave,
	OpCAGetByID:             handleCAGetByID,
	OpCAGetByName:           handleCAGetByName,
	OpCAList:                handleCAList,
	OpSecretSaveVersion:     handleSecretSaveVersion,
	OpSecretGetLatest:       handleSecretGetLatest,
	OpSecretGetVersion:      handleSecretGetVersion,
	OpSecretListByPath:      handleSecretListByPath,
	OpSecretNextVersion:     handleSecretNextVersion,
	OpSecretPut:             handleSecretPut,
	OpSecretDestroyVer:      handleSecretDestroyVer,
	OpSecretUpdateDEKEnc:    handleSecretUpdateDEKEnc,
	OpPKIRoleSave:           handlePKIRoleSave,
	OpPKIRoleGet:            handlePKIRoleGet,
	OpPKIRoleList:           handlePKIRoleList,
	OpAuditAppend:           handleAuditAppend,
	OpAuditList:             handleAuditList,
	OpAuditLatestHash:       handleAuditLatestHash,
	OpRevoke:                handleRevoke,
	OpRevokeIs:              handleRevokeIs,
	OpRevokeListByCA:        handleRevokeListByCA,
	OpLeaseSave:             handleLeaseSave,
	OpLeaseGet:              handleLeaseGet,
	OpLeaseList:             handleLeaseList,
	OpLeaseListExpired:      handleLeaseListExpired,
	OpLeaseRevoke:           handleLeaseRevoke,
	OpLeaseCountActive:      handleLeaseCountActive,
	OpPolicySave:            handlePolicySave,
	OpPolicyGet:             handlePolicyGet,
	OpPolicyList:            handlePolicyList,
	OpPolicyDelete:          handlePolicyDelete,
	OpRoleSave:              handleRoleSave,
	OpRoleGet:               handleRoleGet,
	OpRoleList:              handleRoleList,
	OpRoleDelete:            handleRoleDelete,
	OpDBRoleSave:            handleDBRoleSave,
	OpDBRoleGet:             handleDBRoleGet,
	OpDBRoleList:            handleDBRoleList,
	OpDBRoleDelete:          handleDBRoleDelete,
	OpSSHRoleSave:           handleSSHRoleSave,
	OpSSHRoleGet:            handleSSHRoleGet,
	OpSSHRoleList:           handleSSHRoleList,
	OpSSHRoleDelete:         handleSSHRoleDelete,
	OpIssuedSave:            handleIssuedSave,
	OpIssuedGetBySerial:     handleIssuedGetBySerial,
	OpIssuedList:            handleIssuedList,
	OpIssuedListExpiring:    handleIssuedListExpiring,
	OpImportSnapshot:        handleImportSnapshot,
	OpExportSnapshot:        handleExportSnapshot,
	OpTokenSave:             handleTokenSave,
	OpTokenGet:              handleTokenGet,
	OpTokenRevoke:           handleTokenRevoke,
	OpTokenList:             handleTokenList,
	OpTokenListExpired:      handleTokenListExpired,
	OpMachineIdentitySave:   handleMachineIdentitySave,
	OpMachineIdentityGet:    handleMachineIdentityGet,
	OpMachineIdentityList:   handleMachineIdentityList,
	OpMachineIdentityRevoke: handleMachineIdentityRevoke,
	OpRotationPolicySave:    handleRotationPolicySave,
	OpRotationPolicyGet:     handleRotationPolicyGet,
	OpRotationPolicyList:    handleRotationPolicyList,
	OpRotationPolicyDelete:  handleRotationPolicyDelete,
}

func handleCASave(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var ca pki.CA
	if err := json.Unmarshal(payload, &ca); err != nil {
		return nil, err
	}
	return nil, s.CA.Save(ctx, &ca)
}

func handleCAGetByID(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ ID uuid.UUID }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.CA.GetByID(ctx, req.ID)
}

func handleCAGetByName(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Name string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.CA.GetByName(ctx, req.Name)
}

func handleCAList(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.CA.List(ctx)
}

func handleSecretSaveVersion(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var sv secrets.SecretVersion
	if err := json.Unmarshal(payload, &sv); err != nil {
		return nil, err
	}
	return nil, s.Secret.SaveVersion(ctx, &sv)
}

func handleSecretUpdateDEKEnc(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct {
		Path    string
		Version int
		DEKEnc  []byte
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return nil, s.Secret.UpdateDEKEnc(ctx, req.Path, req.Version, req.DEKEnc)
}

func handleSecretGetLatest(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Path string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Secret.GetLatest(ctx, req.Path)
}

func handleSecretGetVersion(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct {
		Path    string
		Version int
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Secret.GetVersion(ctx, req.Path, req.Version)
}

func handleSecretListByPath(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Prefix string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Secret.ListByPath(ctx, req.Prefix)
}

func handleSecretNextVersion(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Path string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Secret.NextVersion(ctx, req.Path)
}

func handleSecretPut(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct {
		SecretVersion secrets.SecretVersion
		CasVersion    *int
		MaxVersions   int
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Secret.PutAtomic(ctx, &req.SecretVersion, req.CasVersion, req.MaxVersions)
}

func handleSecretDestroyVer(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct {
		Path    string
		Version int
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return nil, s.Secret.DestroyVersion(ctx, req.Path, req.Version)
}

func handlePKIRoleSave(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var role pki.Role
	if err := json.Unmarshal(payload, &role); err != nil {
		return nil, err
	}
	if _, err := s.CA.GetByName(ctx, role.CAName); err != nil {
		return nil, err
	}
	if err := s.PKIRole.Save(ctx, &role); err != nil {
		return nil, err
	}
	return role, nil
}

func handlePKIRoleGet(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Name string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.PKIRole.Get(ctx, req.Name)
}

func handlePKIRoleList(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.PKIRole.List(ctx)
}

func handleAuditAppend(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var entry audit.Entry
	if err := json.Unmarshal(payload, &entry); err != nil {
		return nil, err
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	prevHash, err := s.Audit.LatestHash(ctx)
	if err != nil {
		return nil, err
	}
	entry.Hash = auditsvc.EntryHash(prevHash, entry.Actor, entry.Action, entry.Resource, entry.Status, entry.Details, entry.Timestamp)
	if err := s.Audit.Append(ctx, &entry); err != nil {
		return nil, err
	}
	return entry, nil
}

func handleAuditList(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var opts repository.AuditListOptions
	if err := json.Unmarshal(payload, &opts); err != nil {
		return nil, err
	}
	return s.Audit.List(ctx, opts)
}

func handleAuditLatestHash(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.Audit.LatestHash(ctx)
}

func handleRevoke(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var cert repository.RevokedCertificate
	if err := json.Unmarshal(payload, &cert); err != nil {
		return nil, err
	}
	return nil, s.Revoke.Revoke(ctx, &cert)
}

func handleRevokeIs(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Serial string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Revoke.IsRevoked(ctx, req.Serial)
}

func handleRevokeListByCA(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ CAID uuid.UUID }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Revoke.ListByCA(ctx, req.CAID)
}

func handleLeaseSave(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var lease secrets.Lease
	if err := json.Unmarshal(payload, &lease); err != nil {
		return nil, err
	}
	return nil, s.Lease.Save(ctx, &lease)
}

func handleLeaseGet(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ ID string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Lease.Get(ctx, req.ID)
}

func handleLeaseList(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.Lease.List(ctx)
}

func handleLeaseListExpired(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct {
		Before time.Time
		Limit  int
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Lease.ListExpired(ctx, req.Before, req.Limit)
}

func handleLeaseRevoke(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct {
		ID        string
		RevokedAt time.Time
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return nil, s.Lease.Revoke(ctx, req.ID, req.RevokedAt)
}

func handleLeaseCountActive(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.Lease.CountActive(ctx)
}

func handlePolicySave(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var policy domainauth.Policy
	if err := json.Unmarshal(payload, &policy); err != nil {
		return nil, err
	}
	if err := s.Policy.Save(ctx, &policy); err != nil {
		return nil, err
	}
	return policy, nil
}

func handlePolicyGet(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Name string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Policy.GetByName(ctx, req.Name)
}

func handlePolicyList(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.Policy.List(ctx)
}

func handlePolicyDelete(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Name string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return nil, s.Policy.Delete(ctx, req.Name)
}

func handleRoleSave(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var role domainauth.Role
	if err := json.Unmarshal(payload, &role); err != nil {
		return nil, err
	}
	return nil, s.Role.Save(ctx, &role)
}

func handleRoleGet(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Name string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Role.Get(ctx, req.Name)
}

func handleRoleList(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.Role.List(ctx)
}

func handleRoleDelete(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Name string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return nil, s.Role.Delete(ctx, req.Name)
}

func handleDBRoleSave(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var role secrets.DatabaseRole
	if err := json.Unmarshal(payload, &role); err != nil {
		return nil, err
	}
	return nil, s.DBRole.Save(ctx, &role)
}

func handleDBRoleGet(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Name string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.DBRole.Get(ctx, req.Name)
}

func handleDBRoleList(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.DBRole.List(ctx)
}

func handleDBRoleDelete(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Name string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return nil, s.DBRole.Delete(ctx, req.Name)
}

func handleSSHRoleSave(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var role secrets.SSHRole
	if err := json.Unmarshal(payload, &role); err != nil {
		return nil, err
	}
	return nil, s.SSHRole.Save(ctx, &role)
}

func handleSSHRoleGet(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Name string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.SSHRole.Get(ctx, req.Name)
}

func handleSSHRoleList(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.SSHRole.List(ctx)
}

func handleSSHRoleDelete(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Name string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return nil, s.SSHRole.Delete(ctx, req.Name)
}

func handleIssuedSave(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var cert pki.IssuedCertificate
	if err := json.Unmarshal(payload, &cert); err != nil {
		return nil, err
	}
	return nil, s.IssuedCert.Save(ctx, &cert)
}

func handleIssuedGetBySerial(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct {
		CAID   uuid.UUID
		Serial string
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.IssuedCert.GetBySerial(ctx, req.CAID, req.Serial)
}

func handleIssuedList(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.IssuedCert.List(ctx)
}

func handleIssuedListExpiring(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct {
		Before time.Time
		Limit  int
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.IssuedCert.ListExpiring(ctx, req.Before, req.Limit)
}

func handleImportSnapshot(s *Store, _ context.Context, payload json.RawMessage) (any, error) {
	var snapshot backup.Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return nil, err
	}
	return nil, s.ImportSnapshot(&snapshot)
}

func handleExportSnapshot(s *Store, _ context.Context, payload json.RawMessage) (any, error) {
	var opts backup.ExportOptions
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &opts); err != nil {
			return nil, err
		}
	}
	return s.ExportSnapshot(opts.IncludeAudit)
}

func handleTokenSave(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var token domainauth.ClientToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, err
	}
	return nil, s.Token.Save(ctx, &token)
}

func handleTokenGet(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ ID string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Token.Get(ctx, req.ID)
}

func handleTokenRevoke(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct {
		ID        string
		RevokedAt time.Time
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return nil, s.Token.Revoke(ctx, req.ID, req.RevokedAt)
}

func handleTokenList(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.Token.List(ctx)
}

func handleTokenListExpired(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct {
		Before time.Time
		Limit  int
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.Token.ListExpired(ctx, req.Before, req.Limit)
}

func handleMachineIdentitySave(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var id domainauth.MachineIdentity
	if err := json.Unmarshal(payload, &id); err != nil {
		return nil, err
	}
	return nil, s.MachineIdentity.Save(ctx, &id)
}

func handleMachineIdentityGet(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ ID string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.MachineIdentity.Get(ctx, req.ID)
}

func handleMachineIdentityList(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.MachineIdentity.List(ctx)
}

func handleMachineIdentityRevoke(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ ID string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return nil, s.MachineIdentity.Revoke(ctx, req.ID)
}

func handleRotationPolicySave(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var policy secrets.RotationPolicy
	if err := json.Unmarshal(payload, &policy); err != nil {
		return nil, err
	}
	return nil, s.RotationPolicy.Save(ctx, &policy)
}

func handleRotationPolicyGet(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Path string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return s.RotationPolicy.Get(ctx, req.Path)
}

func handleRotationPolicyList(s *Store, ctx context.Context, _ json.RawMessage) (any, error) {
	return s.RotationPolicy.List(ctx)
}

func handleRotationPolicyDelete(s *Store, ctx context.Context, payload json.RawMessage) (any, error) {
	var req struct{ Path string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return nil, s.RotationPolicy.Delete(ctx, req.Path)
}
