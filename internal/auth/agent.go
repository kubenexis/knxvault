// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/utils"
)

const (
	defaultAgentTTL = 15 * time.Minute
	// maxAgentTTL is a hard server-side cap (W50-12).
	maxAgentTTL = time.Hour
)

// AgentDelegateRequest scopes a short-lived delegated token for an AI agent.
type AgentDelegateRequest struct {
	AgentID        string
	PathPrefix     string
	AllowedActions []string
	Policies       []string
	TTL            time.Duration
}

// DelegateAgent issues a non-renewable agent token from an authenticated parent principal.
func (s *Service) DelegateAgent(ctx context.Context, parent Principal, req AgentDelegateRequest) (string, *TokenRecord, error) {
	if req.AgentID == "" {
		return "", nil, common.New(common.ErrCodeValidation, "agent_id is required")
	}
	if req.PathPrefix == "" {
		return "", nil, common.New(common.ErrCodeValidation, "path_prefix is required")
	}
	if len(req.AllowedActions) == 0 {
		return "", nil, common.New(common.ErrCodeValidation, "allowed_actions is required")
	}
	prefix := normalizeAgentPathPrefix(req.PathPrefix, req.AgentID)
	// W52: require explicit policy subset — do not inherit full parent admin policies.
	if len(req.Policies) == 0 {
		return "", nil, common.New(common.ErrCodeValidation, "policies are required for agent delegation (explicit subset of parent policies)")
	}
	if err := s.validateDelegatedPolicies(parent.Policies, req.Policies); err != nil {
		return "", nil, err
	}
	policies := append([]string(nil), req.Policies...)
	ttl := req.TTL
	if ttl <= 0 {
		ttl = defaultAgentTTL
	}
	if ttl > maxAgentTTL {
		ttl = maxAgentTTL
	}
	parentID := parent.Subject
	if parentID == "" {
		parentID = parent.TokenID
	}
	subject := fmt.Sprintf("agent:%s", req.AgentID)
	token, record, err := s.tokens.CreateAgent(ctx, subject, policies, ttl, AgentTokenScope{
		ParentIdentityID: parentID,
		AgentID:          req.AgentID,
		AllowedActions:   req.AllowedActions,
		PathPrefix:       prefix,
	})
	if err != nil {
		return "", nil, err
	}
	if s.nhi != nil {
		nhiID := domainauth.NHIKey(domainauth.IdentityTypeAgent, "", "", req.AgentID)
		_ = s.nhi.UpsertFromLogin(ctx, &domainauth.MachineIdentity{
			ID:               nhiID,
			Type:             domainauth.IdentityTypeAgent,
			BoundName:        req.AgentID,
			Policies:         policies,
			MaxTTL:           int64(ttl.Seconds()),
			ParentIdentityID: parentID,
		})
	}
	if s.audit != nil {
		_ = s.audit.Record(ctx, parent.Subject, "auth.agent.delegate", "auth/agent/"+req.AgentID, "success", map[string]any{
			"parent_identity_id": parentID,
			"agent_id":           req.AgentID,
			"path_prefix":        prefix,
			"allowed_actions":    req.AllowedActions,
		})
	}
	return token, record, nil
}

// AgentTokenScope carries delegation constraints stored on the token record.
type AgentTokenScope struct {
	ParentIdentityID string
	AgentID          string
	AllowedActions   []string
	PathPrefix       string
}

// CreateAgent issues a scoped agent token.
func (s *TokenStore) CreateAgent(ctx context.Context, subject string, policies []string, ttl time.Duration, scope AgentTokenScope) (string, *TokenRecord, error) {
	if ttl <= 0 {
		ttl = defaultAgentTTL
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	token := "knxv_" + base64.RawURLEncoding.EncodeToString(raw)
	record := TokenRecord{
		ID:               hashToken(token),
		Subject:          subject,
		Policies:         policies,
		ExpiresAt:        time.Now().UTC().Add(ttl),
		Renewable:        false,
		ParentIdentityID: scope.ParentIdentityID,
		AgentID:          scope.AgentID,
		AllowedActions:   append([]string(nil), scope.AllowedActions...),
		PathPrefix:       scope.PathPrefix,
	}
	if err := s.save(ctx, record); err != nil {
		return "", nil, err
	}
	copy := record
	return token, &copy, nil
}

func (s *Service) validateDelegatedPolicies(parentPolicies, requested []string) error {
	if s.rbac == nil {
		return common.New(common.ErrCodeInternal, "rbac not configured")
	}
	parentSet := make(map[string]struct{})
	for _, name := range s.rbac.ResolvePolicyNames(parentPolicies) {
		parentSet[name] = struct{}{}
	}
	for _, name := range requested {
		for _, resolved := range s.rbac.ResolvePolicyNames([]string{name}) {
			if _, ok := parentSet[resolved]; !ok {
				return common.New(common.ErrCodeForbidden, "cannot delegate policy outside parent scope")
			}
		}
	}
	return nil
}

// ParseAgentDelegateTTL parses optional TTL strings for delegation.
func ParseAgentDelegateTTL(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return defaultAgentTTL, nil
	}
	return utils.ParseTTL(raw)
}

func normalizeAgentPathPrefix(prefix, agentID string) string {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	// Reject path traversal in delegated agent scopes.
	if strings.Contains(prefix, "..") {
		prefix = ""
	}
	if prefix == "" {
		prefix = "agent/" + agentID
	}
	if !strings.HasPrefix(prefix, "agent/") {
		prefix = "agent/" + prefix
	}
	// Collapse accidental double slashes and trailing dots.
	prefix = strings.ReplaceAll(prefix, "//", "/")
	return strings.Trim(prefix, "/") + "/"
}

// ActionAllowedForPrincipal checks delegated action constraints when present.
func ActionAllowedForPrincipal(principal Principal, action string) bool {
	if len(principal.AllowedActions) == 0 {
		return true
	}
	for _, allowed := range principal.AllowedActions {
		if domainauth.MatchAction(allowed, action) {
			return true
		}
	}
	return false
}

// KVPathAllowedForPrincipal enforces agent path-prefix scope on KV resources.
func KVPathAllowedForPrincipal(principal Principal, resource string) bool {
	if principal.PathPrefix == "" {
		return true
	}
	kvPrefix := "secrets/kv/" + strings.TrimSuffix(principal.PathPrefix, "/")
	return strings.HasPrefix(resource, kvPrefix+"/") || resource == kvPrefix
}
