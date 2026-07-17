// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

// AppRole is a registered AppRole credential pair for Vault-compatible login.
// Used by cert-manager's vault.auth.appRole (and other Vault clients).
type AppRole struct {
	RoleID   string
	Subject  string
	Policies []string
	// secretHash is sha256 hex of the secret_id (never store raw secret_id).
	secretHash string
}

// AppRoleStore holds AppRole definitions. Optionally file-persisted (W50-04)
// and/or Raft-replicated via SecretRepository (W53).
type AppRoleStore struct {
	mu          sync.RWMutex
	roles       map[string]AppRole // key: role_id
	persistPath string
	replicator  *AppRoleReplicator
}

// NewAppRoleStore constructs an empty AppRole store.
func NewAppRoleStore() *AppRoleStore {
	return &AppRoleStore{roles: make(map[string]AppRole)}
}

// Register stores or replaces an AppRole. secretID is hashed before storage.
func (s *AppRoleStore) Register(roleID, secretID, subject string, policies []string) error {
	if s == nil {
		return common.New(common.ErrCodeInternal, "approle store not configured")
	}
	roleID = strings.TrimSpace(roleID)
	secretID = strings.TrimSpace(secretID)
	if roleID == "" || secretID == "" {
		return common.New(common.ErrCodeValidation, "role_id and secret_id are required")
	}
	if len(secretID) < 16 {
		return common.New(common.ErrCodeValidation, "secret_id must be at least 16 characters")
	}
	if len(policies) == 0 {
		return common.New(common.ErrCodeValidation, "policies are required")
	}
	if subject == "" {
		subject = "approle:" + roleID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[roleID] = AppRole{
		RoleID:     roleID,
		Subject:    subject,
		Policies:   append([]string(nil), policies...),
		secretHash: hashSecretID(roleID, secretID),
	}
	s.saveLocked()
	return nil
}

// Delete removes an AppRole by role_id.
func (s *AppRoleStore) Delete(roleID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.roles, roleID)
	s.saveLocked()
}

// Authenticate validates role_id + secret_id and returns the AppRole metadata.
func (s *AppRoleStore) Authenticate(roleID, secretID string) (*AppRole, error) {
	if s == nil {
		return nil, common.New(common.ErrCodeUnauthorized, "invalid role_id or secret_id")
	}
	roleID = strings.TrimSpace(roleID)
	secretID = strings.TrimSpace(secretID)
	if roleID == "" || secretID == "" {
		return nil, common.New(common.ErrCodeValidation, "role_id and secret_id are required")
	}
	s.mu.RLock()
	role, ok := s.roles[roleID]
	s.mu.RUnlock()
	if !ok {
		return nil, common.New(common.ErrCodeUnauthorized, "invalid role_id or secret_id")
	}
	want, err := hex.DecodeString(role.secretHash)
	if err != nil {
		return nil, common.New(common.ErrCodeInternal, "approle corrupt")
	}
	got := sha256.Sum256([]byte(roleID + "\x00" + secretID))
	// W79: salted hash only (re-register AppRoles created before W78).
	if subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return nil, common.New(common.ErrCodeUnauthorized, "invalid role_id or secret_id")
	}
	copy := role
	return &copy, nil
}

// hashSecretID returns salted SHA-256 hex (role_id as salt) — W78.
func hashSecretID(roleID, secretID string) string {
	sum := sha256.Sum256([]byte(roleID + "\x00" + secretID))
	return hex.EncodeToString(sum[:])
}

// SetAppRoleStore configures AppRole authentication on the auth service.
func (s *Service) SetAppRoleStore(store *AppRoleStore) {
	if s == nil {
		return
	}
	s.approles = store
}

// AppRoles returns the AppRole store (may be nil).
func (s *Service) AppRoles() *AppRoleStore {
	if s == nil {
		return nil
	}
	return s.approles
}

// EnsureAppRoleStore lazily creates an in-memory AppRole store.
func (s *Service) EnsureAppRoleStore() *AppRoleStore {
	if s == nil {
		return nil
	}
	if s.approles == nil {
		s.approles = NewAppRoleStore()
	}
	return s.approles
}

// RegisterAppRole registers credentials for Vault AppRole login.
func (s *Service) RegisterAppRole(roleID, secretID, subject string, policies []string) error {
	return s.EnsureAppRoleStore().Register(roleID, secretID, subject, policies)
}

// LoginAppRole authenticates with role_id/secret_id and issues a client token.
func (s *Service) LoginAppRole(ctx context.Context, roleID, secretID string) (string, *TokenRecord, error) {
	auditCtx := loginAuditFromContext(ctx, "approle")
	lockKey := LoginLockoutKey("approle", auditCtx)
	if s.lockout != nil && s.lockout.IsLockedAny(LoginLockoutKeys("approle", auditCtx)...) {
		auditCtx.FailureReason = "identity locked out"
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, common.New(common.ErrCodeForbidden, "identity locked out")
	}
	role, err := s.EnsureAppRoleStore().Authenticate(roleID, secretID)
	if err != nil {
		if s.lockout != nil {
			s.noteLockoutFailure(ctx, lockKey, auditCtx)
		}
		auditCtx.FailureReason = err.Error()
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, err
	}
	token, record, err := s.tokens.Issue(ctx, role.Subject, role.Policies)
	if err != nil {
		auditCtx.FailureReason = err.Error()
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, err
	}
	if s.lockout != nil {
		s.lockout.Clear(lockKey)
	}
	auditCtx.ClientIdentity = role.Subject
	s.recordLoginAudit(ctx, true, auditCtx)
	return token, record, nil
}
