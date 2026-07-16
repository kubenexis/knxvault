package auth

import (
	"context"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

// LoginAuditContext carries request metadata for authentication audit (W43-01/02).
type LoginAuditContext struct {
	AuthMethod     string
	SourceIP       string
	ClientIdentity string
	RequestID      string
	Namespace      string
	FailureReason  string
}

// recordLoginAudit emits auth.login or auth.login.failed events.
func (s *Service) recordLoginAudit(ctx context.Context, success bool, auditCtx LoginAuditContext) {
	if s == nil || s.audit == nil {
		return
	}
	action := "auth.login.failed"
	status := "failure"
	if success {
		action = "auth.login"
		status = "success"
	}
	details := map[string]any{
		"auth_method":     auditCtx.AuthMethod,
		"source_ip":       auditCtx.SourceIP,
		"client_identity": auditCtx.ClientIdentity,
		"request_id":      auditCtx.RequestID,
		"namespace":       auditCtx.Namespace,
	}
	if auditCtx.FailureReason != "" {
		details["failure_reason"] = auditCtx.FailureReason
	}
	actor := auditCtx.ClientIdentity
	if actor == "" {
		actor = "anonymous"
	}
	_ = s.audit.Record(ctx, actor, action, "auth/"+auditCtx.AuthMethod, status, details)
}

func (s *Service) recordLockoutAudit(ctx context.Context, lockKey string, auditCtx LoginAuditContext) {
	if s == nil || s.audit == nil {
		return
	}
	details := map[string]any{
		"auth_method": auditCtx.AuthMethod,
		"source_ip":   auditCtx.SourceIP,
		"lockout_key": lockKey,
		"request_id":  auditCtx.RequestID,
	}
	actor := auditCtx.SourceIP
	if actor == "" {
		actor = "anonymous"
	}
	_ = s.audit.Record(ctx, actor, "auth.lockout", "auth/"+auditCtx.AuthMethod, "failure", details)
}

// ClearLockout removes lockout state for an identity (W43-04 break-glass).
func (s *Service) ClearLockout(ctx context.Context, actor, authMethod, sourceIP string) {
	if s == nil || s.lockout == nil {
		return
	}
	key := LockoutKey(authMethod, sourceIP)
	s.lockout.Clear(key)
	if s.audit != nil {
		_ = s.audit.Record(ctx, actor, "auth.lockout.clear", "auth/"+authMethod, "success", map[string]any{
			"auth_method": authMethod,
			"source_ip":   sourceIP,
			"lockout_key": key,
		})
	}
}

// CheckMFA validates OIDC MFA claims for roles with require_mfa (W44-03).
func CheckMFA(requireMFA bool, claims map[string]any) error {
	if !requireMFA {
		return nil
	}
	if acr, ok := claims["acr"]; ok {
		switch v := acr.(type) {
		case string:
			if v == "mfa" || v == "urn:mace:incommon:iap:silver" {
				return nil
			}
		case float64:
			if v >= 2 {
				return nil
			}
		}
	}
	if amr, ok := claims["amr"]; ok {
		switch v := amr.(type) {
		case string:
			if v == "mfa" || v == "otp" || v == "hwk" {
				return nil
			}
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok && (s == "mfa" || s == "otp" || s == "hwk") {
					return nil
				}
			}
		}
	}
	return common.New(common.ErrCodeForbidden, "mfa required for administrative role")
}

func (s *Service) noteLockoutFailure(ctx context.Context, lockKey string, auditCtx LoginAuditContext) {
	if s.lockout == nil {
		return
	}
	// Prefer identity-scoped key when known; fall back to provided lockKey / IP (W50-18).
	// Record a single primary key so dual IP+identity increments do not double-count toward threshold.
	primary := LoginLockoutKey(auditCtx.AuthMethod, auditCtx)
	if primary == "" || primary == LockoutKey(auditCtx.AuthMethod, "unknown") {
		if lockKey != "" {
			primary = lockKey
		}
	}
	if s.lockout.RecordFailure(primary) {
		s.recordLockoutAudit(ctx, primary, auditCtx)
	}
}

func (s *Service) recordLoginFailure(ctx context.Context, lockKey string, auditCtx LoginAuditContext, reason string) {
	auditCtx.FailureReason = reason
	s.recordLoginAudit(ctx, false, auditCtx)
	s.noteLockoutFailure(ctx, lockKey, auditCtx)
}

// LoginWithTokenEndpoint authenticates via POST /auth/token with lockout and audit (W43-01/04).
func (s *Service) LoginWithTokenEndpoint(ctx context.Context, token string) (*TokenRecord, error) {
	auditCtx := loginAuditFromContext(ctx, "token")
	lockKey := LoginLockoutKey("token", auditCtx)
	if s.lockout != nil && s.lockout.IsLockedAny(LoginLockoutKeys("token", auditCtx)...) {
		auditCtx.FailureReason = "identity locked out"
		s.recordLoginAudit(ctx, false, auditCtx)
		return nil, common.New(common.ErrCodeForbidden, "identity locked out")
	}
	if token == "" {
		s.recordLoginFailure(ctx, lockKey, auditCtx, "token is required")
		return nil, common.New(common.ErrCodeValidation, "token is required")
	}
	record, err := s.tokens.Authenticate(ctx, token)
	if err != nil {
		s.recordLoginFailure(ctx, lockKey, auditCtx, "invalid token")
		return nil, err
	}
	auditCtx.ClientIdentity = record.Subject
	if s.lockout != nil {
		s.lockout.RecordSuccess(lockKey)
	}
	return record, nil
}

// RecordTokenLogin records token-based login audit from handlers.
func (s *Service) RecordTokenLogin(ctx context.Context, subject string, success bool, reason string) {
	auditCtx := loginAuditFromContext(ctx, "token")
	auditCtx.ClientIdentity = subject
	auditCtx.FailureReason = reason
	s.recordLoginAudit(ctx, success, auditCtx)
}
