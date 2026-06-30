// Package raft implements the Dragonboat-backed vault state machine.
package raft

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

// Command is a replicated state machine operation.
type Command struct {
	Op      string          `json:"op"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Response wraps command results or domain errors.
type Response struct {
	ErrorCode string          `json:"error_code,omitempty"`
	Message   string          `json:"message,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

const (
	OpCASave             = "ca.save"
	OpCAGetByID          = "ca.get_by_id"
	OpCAGetByName        = "ca.get_by_name"
	OpCAList             = "ca.list"
	OpSecretSaveVersion  = "secret.save_version"
	OpSecretPut          = "secret.put"
	OpSecretGetLatest    = "secret.get_latest"
	OpSecretGetVersion   = "secret.get_version"
	OpSecretListByPath   = "secret.list_by_path"
	OpSecretNextVersion  = "secret.next_version"
	OpSecretDestroyVer   = "secret.destroy_version"
	OpPKIRoleSave        = "pki_role.save"
	OpPKIRoleGet         = "pki_role.get"
	OpPKIRoleList        = "pki_role.list"
	OpAuditAppend        = "audit.append"
	OpAuditList          = "audit.list"
	OpAuditLatestHash    = "audit.latest_hash"
	OpRevoke             = "revoke.save"
	OpRevokeIs           = "revoke.is"
	OpRevokeListByCA     = "revoke.list_by_ca"
	OpLeaseSave          = "lease.save"
	OpLeaseGet           = "lease.get"
	OpLeaseList          = "lease.list"
	OpLeaseListExpired   = "lease.list_expired"
	OpLeaseRevoke        = "lease.revoke"
	OpLeaseCountActive   = "lease.count_active"
	OpPolicySave         = "policy.save"
	OpPolicyGet          = "policy.get_by_name"
	OpPolicyList         = "policy.list"
	OpPolicyDelete       = "policy.delete"
	OpRoleSave           = "role.save"
	OpRoleGet            = "role.get"
	OpRoleList           = "role.list"
	OpRoleDelete         = "role.delete"
	OpDBRoleSave         = "db_role.save"
	OpDBRoleGet          = "db_role.get"
	OpDBRoleList         = "db_role.list"
	OpDBRoleDelete       = "db_role.delete"
	OpIssuedSave         = "issued.save"
	OpIssuedGetBySerial  = "issued.get_by_serial"
	OpIssuedList         = "issued.list"
	OpIssuedListExpiring = "issued.list_expiring"
	OpImportSnapshot     = "snapshot.import"
	OpExportSnapshot     = "snapshot.export"
	OpTokenSave          = "token.save"         // #nosec G101 -- Raft command name
	OpTokenGet           = "token.get"          // #nosec G101 -- Raft command name
	OpTokenRevoke        = "token.revoke"       // #nosec G101 -- Raft command name
	OpTokenList          = "token.list"         // #nosec G101 -- Raft command name
	OpTokenListExpired   = "token.list_expired" // #nosec G101 -- Raft command name
)

// readOnlyOps are safe for SyncRead / Lookup; write ops must use Propose.
var readOnlyOps = map[string]struct{}{
	OpCAGetByID:          {},
	OpCAGetByName:        {},
	OpCAList:             {},
	OpSecretGetLatest:    {},
	OpSecretGetVersion:   {},
	OpSecretListByPath:   {},
	OpSecretNextVersion:  {},
	OpPKIRoleGet:         {},
	OpPKIRoleList:        {},
	OpAuditList:          {},
	OpAuditLatestHash:    {},
	OpRevokeIs:           {},
	OpRevokeListByCA:     {},
	OpLeaseGet:           {},
	OpLeaseList:          {},
	OpLeaseListExpired:   {},
	OpLeaseCountActive:   {},
	OpPolicyGet:          {},
	OpPolicyList:         {},
	OpRoleGet:            {},
	OpRoleList:           {},
	OpDBRoleGet:          {},
	OpDBRoleList:         {},
	OpIssuedGetBySerial:  {},
	OpIssuedList:         {},
	OpIssuedListExpiring: {},
	OpExportSnapshot:     {},
	OpTokenGet:           {},
	OpTokenList:          {},
	OpTokenListExpired:   {},
}

// IsReadOnlyOp reports whether op is permitted on the read path.
func IsReadOnlyOp(op string) bool {
	_, ok := readOnlyOps[op]
	return ok
}

func encodeCommand(op string, payload any) ([]byte, error) {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	return json.Marshal(Command{Op: op, Payload: raw})
}

func decodeCommand(data []byte) (Command, error) {
	var cmd Command
	if err := json.Unmarshal(data, &cmd); err != nil {
		return Command{}, err
	}
	if cmd.Op == "" {
		return Command{}, fmt.Errorf("command op is required")
	}
	return cmd, nil
}

func encodeResponse(data any, err error) ([]byte, error) {
	resp := Response{}
	if err != nil {
		var kv *common.KNXVaultError
		if errors.As(err, &kv) {
			resp.ErrorCode = string(kv.Code)
			resp.Message = kv.Message
		} else {
			resp.ErrorCode = string(common.ErrCodeInternal)
			resp.Message = err.Error()
		}
		return json.Marshal(resp)
	}
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		resp.Data = b
	}
	return json.Marshal(resp)
}
