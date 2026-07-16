package auth

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

// CertLoginOptions maps client certificate identity to policies.
type CertLoginOptions struct {
	// DefaultPolicies applied when no role mapping matches.
	DefaultPolicies []string
	// Role map: CN or DNS SAN → role name resolved via RoleResolver.
	// When RoleResolver is set, PoliciesForRole is used.
	RequireVerified bool // if true, reject when peer certs empty (caller enforces TLS)
}

// LoginWithClientCert authenticates a verified TLS client certificate (W34-02 / W53).
// Identity is derived from Subject CN, then first DNS SAN.
func (s *Service) LoginWithClientCert(ctx context.Context, certs []*x509.Certificate, opts CertLoginOptions) (string, *TokenRecord, error) {
	auditCtx := loginAuditFromContext(ctx, "cert")
	lockKey := LoginLockoutKey("cert", auditCtx)
	if s.lockout != nil && s.lockout.IsLockedAny(LoginLockoutKeys("cert", auditCtx)...) {
		auditCtx.FailureReason = "identity locked out"
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, common.New(common.ErrCodeForbidden, "identity locked out")
	}
	if len(certs) == 0 {
		s.recordLoginFailure(ctx, lockKey, auditCtx, "client certificate required")
		return "", nil, common.New(common.ErrCodeUnauthorized, "client certificate required")
	}
	leaf := certs[0]
	// Basic validity window check
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		s.recordLoginFailure(ctx, lockKey, auditCtx, "client certificate not valid at this time")
		return "", nil, common.New(common.ErrCodeUnauthorized, "client certificate not valid at this time")
	}
	identity := strings.TrimSpace(leaf.Subject.CommonName)
	if identity == "" && len(leaf.DNSNames) > 0 {
		identity = strings.TrimSpace(leaf.DNSNames[0])
	}
	if identity == "" {
		s.recordLoginFailure(ctx, lockKey, auditCtx, "client certificate has no CN or DNS SAN")
		return "", nil, common.New(common.ErrCodeUnauthorized, "client certificate has no CN or DNS SAN")
	}
	auditCtx.ClientIdentity = identity

	policies := append([]string(nil), opts.DefaultPolicies...)
	if s.roles != nil {
		// Treat CN as role name when a matching role exists.
		if rolePolicies := s.roles.PoliciesForRole(ctx, identity); len(rolePolicies) > 0 {
			policies = rolePolicies
		}
	}
	if len(policies) == 0 {
		// Fall back to a single synthetic policy name matching identity for RBAC lookup.
		policies = []string{identity}
	}

	token, record, err := s.tokens.Issue(ctx, fmt.Sprintf("cert:%s", identity), policies)
	if err != nil {
		s.recordLoginFailure(ctx, lockKey, auditCtx, err.Error())
		return "", nil, err
	}
	if s.lockout != nil {
		s.lockout.Clear(lockKey)
	}
	s.recordLoginAudit(ctx, true, auditCtx)
	return token, record, nil
}
