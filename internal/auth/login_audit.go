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

// CheckMFA validates OIDC MFA claims for roles with require_mfa (W44-03).
func CheckMFA(requireMFA bool, claims map[string]any) error {
	if !requireMFA {
		return nil
	}
	if acr, _ := claims["acr"].(string); acr == "mfa" || acr == "urn:mace:incommon:iap:silver" {
		return nil
	}
	if amr, ok := claims["amr"].([]any); ok {
		for _, v := range amr {
			if s, ok := v.(string); ok && (s == "mfa" || s == "otp" || s == "hwk") {
				return nil
			}
		}
	}
	return common.New(common.ErrCodeForbidden, "mfa required for administrative role")
}

// RecordTokenLogin records token-based login audit from handlers.
func (s *Service) RecordTokenLogin(ctx context.Context, subject string, success bool, reason string) {
	auditCtx := loginAuditFromContext(ctx, "token")
	auditCtx.ClientIdentity = subject
	auditCtx.FailureReason = reason
	s.recordLoginAudit(ctx, success, auditCtx)
}
