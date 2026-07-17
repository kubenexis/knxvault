// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/infra/k8s"
	"github.com/kubenexis/knxvault/internal/repository"
)

// TokenRecord is a stored client token.
type TokenRecord = domainauth.ClientToken

// TokenStore manages client tokens in memory and optionally via a replicated repository.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]TokenRecord
	repo   repository.TokenRepository
	ttl    time.Duration
}

// NewTokenStore constructs a token store.
func NewTokenStore(ttl time.Duration) *TokenStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &TokenStore{
		tokens: make(map[string]TokenRecord),
		ttl:    ttl,
	}
}

// SetRepository configures replicated token persistence (Raft).
func (s *TokenStore) SetRepository(repo repository.TokenRepository) {
	s.repo = repo
}

// Issue creates a new opaque client token.
func (s *TokenStore) Issue(ctx context.Context, subject string, policies []string) (string, *TokenRecord, error) {
	return s.Create(ctx, subject, policies, s.ttl, true, time.Time{})
}

// Create issues a token with explicit TTL and renewability.
func (s *TokenStore) Create(ctx context.Context, subject string, policies []string, ttl time.Duration, renewable bool, maxExpiresAt time.Time) (string, *TokenRecord, error) {
	if ttl <= 0 {
		ttl = s.ttl
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	token := "knxv_" + base64.RawURLEncoding.EncodeToString(raw)
	record := TokenRecord{
		ID:        hashToken(token),
		Subject:   subject,
		Policies:  policies,
		ExpiresAt: time.Now().UTC().Add(ttl),
		Renewable: renewable,
	}
	if !maxExpiresAt.IsZero() {
		record.MaxExpiresAt = maxExpiresAt
		if record.ExpiresAt.After(maxExpiresAt) {
			record.ExpiresAt = maxExpiresAt
		}
	}
	if err := s.save(ctx, record); err != nil {
		return "", nil, err
	}
	copy := record
	return token, &copy, nil
}

// Renew extends a renewable token's TTL.
func (s *TokenStore) Renew(ctx context.Context, token string, increment time.Duration) (*TokenRecord, error) {
	if increment <= 0 {
		increment = s.ttl
	}
	record, err := s.get(ctx, hashToken(token))
	if err != nil {
		return nil, common.New(common.ErrCodeUnauthorized, "invalid token")
	}
	if record.Revoked {
		return nil, common.New(common.ErrCodeUnauthorized, "token revoked")
	}
	if !record.Renewable {
		return nil, common.New(common.ErrCodeValidation, "token is not renewable")
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		return nil, common.New(common.ErrCodeUnauthorized, "token expired")
	}
	newExpiry := time.Now().UTC().Add(increment)
	if !record.MaxExpiresAt.IsZero() && newExpiry.After(record.MaxExpiresAt) {
		newExpiry = record.MaxExpiresAt
	}
	record.ExpiresAt = newExpiry
	if err := s.save(ctx, *record); err != nil {
		return nil, err
	}
	copy := *record
	return &copy, nil
}

// Revoke invalidates a token immediately.
func (s *TokenStore) Revoke(ctx context.Context, token string) error {
	id := hashToken(token)
	now := time.Now().UTC()
	if s.repo != nil {
		if err := s.repo.Revoke(ctx, id, now); err != nil {
			var kv *common.KNXVaultError
			if errors.As(err, &kv) && kv.Code == common.ErrCodeNotFound {
				return common.New(common.ErrCodeUnauthorized, "invalid token")
			}
			return err
		}
		s.mu.Lock()
		delete(s.tokens, id)
		s.mu.Unlock()
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.tokens[id]
	if !ok {
		return common.New(common.ErrCodeUnauthorized, "invalid token")
	}
	record.Revoked = true
	record.ExpiresAt = now
	s.tokens[id] = record
	return nil
}

// Authenticate validates an opaque client token.
func (s *TokenStore) Authenticate(ctx context.Context, token string) (*TokenRecord, error) {
	record, err := s.get(ctx, hashToken(token))
	if err != nil {
		return nil, common.New(common.ErrCodeUnauthorized, "invalid token")
	}
	if record.Revoked {
		return nil, common.New(common.ErrCodeUnauthorized, "token revoked")
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		return nil, common.New(common.ErrCodeUnauthorized, "token expired")
	}
	copy := *record
	return &copy, nil
}

// DefaultRootTokenTTL is the bootstrap root token lifetime (W50-26).
// Prefer rotating to scoped admin tokens after bootstrap; override via RegisterRootTokenTTL.
const DefaultRootTokenTTL = 72 * time.Hour

// RegisterRootToken registers a bootstrap token hash with DefaultRootTokenTTL.
func (s *TokenStore) RegisterRootToken(ctx context.Context, token string, policies []string) error {
	return s.RegisterRootTokenTTL(ctx, token, policies, DefaultRootTokenTTL)
}

// RegisterRootTokenTTL registers a bootstrap token with an explicit TTL.
// ttl <= 0 uses DefaultRootTokenTTL.
func (s *TokenStore) RegisterRootTokenTTL(ctx context.Context, token string, policies []string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = DefaultRootTokenTTL
	}
	record := TokenRecord{
		ID:        hashToken(token),
		Subject:   "root",
		Policies:  policies,
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	return s.save(ctx, record)
}

func (s *TokenStore) save(ctx context.Context, record TokenRecord) error {
	if s.repo != nil {
		if err := s.repo.Save(ctx, &record); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.tokens[record.ID] = record
	s.mu.Unlock()
	return nil
}

func (s *TokenStore) get(ctx context.Context, id string) (*TokenRecord, error) {
	if s.repo != nil {
		record, err := s.repo.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.tokens[id] = *record
		s.mu.Unlock()
		return record, nil
	}
	s.mu.RLock()
	record, ok := s.tokens[id]
	s.mu.RUnlock()
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "token not found")
	}
	copy := record
	return &copy, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// K8sLoginOptions configures Kubernetes authentication behavior.
type K8sLoginOptions struct {
	RaftEnabled   bool
	InsecureDev   bool
	TokenReviewer k8s.TokenReviewer
}

// RBACSyncer reloads persisted policies into the local RBAC cache.
type RBACSyncer interface {
	SyncRBAC(ctx context.Context) error
}

// MachineIdentityRecorder upserts NHI records on login.
type MachineIdentityRecorder interface {
	UpsertFromLogin(ctx context.Context, identity *domainauth.MachineIdentity) error
	IsRevoked(ctx context.Context, id string) (bool, error)
}

// AuditRecorder appends audit events for authentication flows.
type AuditRecorder interface {
	Record(ctx context.Context, actor, action, resource, status string, details map[string]any) error
}

// Service coordinates authentication flows.
type Service struct {
	tokens             *TokenStore
	rbac               *RBAC
	rbacSync           RBACSyncer
	rbacSyncFailClosed bool
	roles              RoleResolver
	jwtSecret          []byte
	k8s                K8sLoginOptions
	oidc               *OIDCValidator
	oidcTTL            time.Duration
	nhi                MachineIdentityRecorder
	audit              AuditRecorder
	lockout            Lockout
	approles           *AppRoleStore
	ldapBinder         LDAPBinder
	identityResolver   IdentityResolver
	leaseCascade       LeaseCascade
	tokenCleaner       TokenCleaner
	ldapDefaults       *LDAPConfig
}

// LeaseCascade revokes leases when a token is revoked (M-LEASE-1).
type LeaseCascade interface {
	RevokeByTokenID(ctx context.Context, tokenID string) (int, error)
}

// TokenCleaner cleans per-token resources (cubbyhole) on revoke (M-WRAP-1).
type TokenCleaner interface {
	WipeToken(ctx context.Context, tokenID string) error
}

// Lockout is the lockout tracker abstraction (local or cluster-shared).
type Lockout interface {
	IsLocked(key string) bool
	IsLockedAny(keys ...string) bool
	RecordFailure(key string) bool
	RecordSuccess(key string)
	Clear(key string)
}

// RoleResolver resolves role names to policy names.
type RoleResolver interface {
	PoliciesForRole(ctx context.Context, role string) []string
}

// RoleBindingResolver resolves persisted role records for authentication binding checks.
type RoleBindingResolver interface {
	GetStoredRole(ctx context.Context, name string) (*domainauth.Role, error)
}

// NewService constructs an auth service.
func NewService(tokens *TokenStore, rbac *RBAC, jwtSecret string) *Service {
	return &Service{
		tokens:    tokens,
		rbac:      rbac,
		jwtSecret: []byte(jwtSecret),
	}
}

// SetRoleResolver configures dynamic role resolution.
func (s *Service) SetRoleResolver(resolver RoleResolver) {
	s.roles = resolver
}

// SetRBACSyncer configures cluster-wide RBAC cache synchronization.
func (s *Service) SetRBACSyncer(syncer RBACSyncer) {
	s.rbacSync = syncer
}

// SetRBACSyncFailClosed when true denies authorization if SyncRBAC fails (W50-17).
func (s *Service) SetRBACSyncFailClosed(failClosed bool) {
	if s != nil {
		s.rbacSyncFailClosed = failClosed
	}
}

func (s *Service) syncRBAC(ctx context.Context) error {
	if s == nil || s.rbacSync == nil {
		return nil
	}
	err := s.rbacSync.SyncRBAC(ctx)
	if err != nil && s.rbacSyncFailClosed {
		return common.Wrap(common.ErrCodeUnavailable, "rbac sync failed", err)
	}
	return nil
}

// SetK8sLoginOptions configures Kubernetes login validation.
func (s *Service) SetK8sLoginOptions(opts K8sLoginOptions) {
	s.k8s = opts
}

// SetOIDCValidator configures OIDC JWT validation.
func (s *Service) SetOIDCValidator(v *OIDCValidator, defaultTTL time.Duration) {
	s.oidc = v
	s.oidcTTL = defaultTTL
}

// SetMachineIdentityRecorder configures NHI upsert on login.
func (s *Service) SetMachineIdentityRecorder(recorder MachineIdentityRecorder) {
	s.nhi = recorder
}

// SetAuditRecorder configures authentication audit events.
func (s *Service) SetAuditRecorder(recorder AuditRecorder) {
	s.audit = recorder
}

// SetLockoutTracker configures identity lockout after failed logins (local or shared).
func (s *Service) SetLockoutTracker(tracker Lockout) {
	s.lockout = tracker
}

// SimulatePolicy evaluates authorization for policy simulation (W41-04).
func (s *Service) SimulatePolicy(ctx context.Context, policies []string, resource, capability string, req RequestContext) AuthzResult {
	_ = s.syncRBAC(ctx) // simulation still uses last-known policies on soft fail
	return s.rbac.AuthorizeDetailed(s.rbac.ResolvePolicyNames(policies), resource, capability, req)
}

// AuthorizePath checks RBAC for a path-aware resource and capability.
func (s *Service) AuthorizePath(ctx context.Context, principal Principal, resource, capability string) error {
	if !ActionAllowedForPrincipal(principal, capability) {
		return common.New(common.ErrCodeForbidden, "action not allowed for agent token")
	}
	if strings.HasPrefix(resource, "secrets/kv/") && !KVPathAllowedForPrincipal(principal, resource) {
		return common.New(common.ErrCodeForbidden, "path outside agent prefix")
	}
	if err := s.syncRBAC(ctx); err != nil {
		return err
	}
	req := RequestContext{Resource: resource, Action: capability, AgentID: principal.AgentID}
	if existing, ok := RequestContextFromContext(ctx); ok {
		req = existing
	}
	req.Resource = resource
	req.Action = capability
	req.AgentID = principal.AgentID
	if !s.rbac.Authorize(principal.Policies, resource, capability, req) {
		return common.New(common.ErrCodeForbidden, "access denied")
	}
	return nil
}

// LoginWithToken authenticates an opaque token.
func (s *Service) LoginWithToken(ctx context.Context, token string) (*TokenRecord, error) {
	return s.tokens.Authenticate(ctx, token)
}

// LoginKubernetes validates a service account JWT and maps it to a role.
func (s *Service) LoginKubernetes(ctx context.Context, role, jwtToken string) (string, *TokenRecord, error) {
	auditCtx := loginAuditFromContext(ctx, "kubernetes")
	lockKey := LoginLockoutKey("kubernetes", auditCtx)
	if s.lockout != nil && s.lockout.IsLockedAny(LoginLockoutKeys("kubernetes", auditCtx)...) {
		auditCtx.FailureReason = "identity locked out"
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, common.New(common.ErrCodeForbidden, "identity locked out")
	}
	if jwtToken == "" {
		auditCtx.FailureReason = "jwt is required"
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, common.New(common.ErrCodeValidation, "jwt is required")
	}
	if role == "" {
		auditCtx.FailureReason = "role is required"
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, common.New(common.ErrCodeValidation, "role is required")
	}

	identity, subject, err := s.validateKubernetesJWT(ctx, role, jwtToken)
	auditCtx.ClientIdentity = subject
	auditCtx.Namespace = identity.Namespace
	if err != nil {
		auditCtx.FailureReason = "kubernetes jwt validation failed"
		s.recordLoginAudit(ctx, false, auditCtx)
		s.noteLockoutFailure(ctx, lockKey, auditCtx)
		return "", nil, err
	}

	bindingResolver, ok := s.roles.(RoleBindingResolver)
	if !ok {
		auditCtx.FailureReason = "kubernetes login requires persisted roles"
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, common.New(common.ErrCodeForbidden, "kubernetes login requires persisted roles")
	}
	storedRole, err := bindingResolver.GetStoredRole(ctx, role)
	if err != nil {
		auditCtx.FailureReason = "role not found"
		s.recordLoginAudit(ctx, false, auditCtx)
		s.noteLockoutFailure(ctx, lockKey, auditCtx)
		return "", nil, common.Wrap(common.ErrCodeForbidden, "role not found", err)
	}
	if storedRole.AuthMethod != "" && storedRole.AuthMethod != domainauth.AuthMethodKubernetes {
		auditCtx.FailureReason = "role does not allow kubernetes login"
		s.recordLoginAudit(ctx, false, auditCtx)
		s.noteLockoutFailure(ctx, lockKey, auditCtx)
		return "", nil, common.New(common.ErrCodeForbidden, "role does not allow kubernetes login")
	}
	if err := MatchServiceAccountBinding(storedRole, identity); err != nil {
		auditCtx.FailureReason = "service account binding mismatch"
		s.recordLoginAudit(ctx, false, auditCtx)
		s.noteLockoutFailure(ctx, lockKey, auditCtx)
		return "", nil, err
	}
	policies := storedRole.Policies
	if s.roles != nil {
		policies = s.roles.PoliciesForRole(ctx, role)
	}
	if len(policies) == 0 {
		auditCtx.FailureReason = "role has no policies"
		s.recordLoginAudit(ctx, false, auditCtx)
		s.noteLockoutFailure(ctx, lockKey, auditCtx)
		return "", nil, common.New(common.ErrCodeForbidden, "role has no policies")
	}
	nhiID := domainauth.NHIKey(domainauth.IdentityTypeK8sSA, identity.Namespace, identity.Name, subject)
	if s.nhi != nil {
		revoked, err := s.nhi.IsRevoked(ctx, nhiID)
		if err != nil {
			return "", nil, common.Wrap(common.ErrCodeUnavailable, "identity check failed", err)
		}
		if revoked {
			return "", nil, common.New(common.ErrCodeForbidden, "machine identity revoked")
		}
		_ = s.nhi.UpsertFromLogin(ctx, &domainauth.MachineIdentity{
			ID:             nhiID,
			Type:           domainauth.IdentityTypeK8sSA,
			BoundNamespace: identity.Namespace,
			BoundName:      identity.Name,
			Policies:       policies,
		})
	}
	if s.lockout != nil {
		s.lockout.RecordSuccess(lockKey)
	}
	s.recordLoginAudit(ctx, true, auditCtx)
	return s.tokens.Issue(ctx, subject, policies)
}

// LoginOIDC validates an OIDC JWT and maps it to a role.
func (s *Service) LoginOIDC(ctx context.Context, role, jwtToken string) (string, *TokenRecord, error) {
	auditCtx := loginAuditFromContext(ctx, "oidc")
	lockKey := LoginLockoutKey("oidc", auditCtx)
	if s.lockout != nil && s.lockout.IsLockedAny(LoginLockoutKeys("oidc", auditCtx)...) {
		auditCtx.FailureReason = "identity locked out"
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, common.New(common.ErrCodeForbidden, "identity locked out")
	}
	if jwtToken == "" {
		auditCtx.FailureReason = "jwt is required"
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, common.New(common.ErrCodeValidation, "jwt is required")
	}
	if role == "" {
		auditCtx.FailureReason = "role is required"
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, common.New(common.ErrCodeValidation, "role is required")
	}
	if s.oidc == nil {
		auditCtx.FailureReason = "oidc not configured"
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, common.New(common.ErrCodeUnauthorized, "oidc authentication not configured")
	}
	var oidcCfg *domainauth.OIDCConfig
	var requireMFA bool
	if bindingResolver, ok := s.roles.(RoleBindingResolver); ok {
		storedRole, err := bindingResolver.GetStoredRole(ctx, role)
		if err != nil {
			auditCtx.FailureReason = "role not found"
			s.recordLoginAudit(ctx, false, auditCtx)
			return "", nil, common.Wrap(common.ErrCodeForbidden, "role not found", err)
		}
		if storedRole.AuthMethod != "" && storedRole.AuthMethod != domainauth.AuthMethodOIDC {
			auditCtx.FailureReason = "role does not allow oidc login"
			s.recordLoginAudit(ctx, false, auditCtx)
			return "", nil, common.New(common.ErrCodeForbidden, "role does not allow oidc login")
		}
		oidcCfg = storedRole.OIDC
		requireMFA = storedRole.RequireMFA
	}
	if oidcCfg == nil {
		auditCtx.FailureReason = "oidc not configured for role"
		s.recordLoginAudit(ctx, false, auditCtx)
		return "", nil, common.New(common.ErrCodeValidation, "oidc not configured for role")
	}
	subject, claims, err := s.oidc.Validate(ctx, oidcCfg, jwtToken)
	auditCtx.ClientIdentity = subject
	if err != nil {
		auditCtx.FailureReason = "oidc jwt validation failed"
		s.recordLoginAudit(ctx, false, auditCtx)
		s.noteLockoutFailure(ctx, lockKey, auditCtx)
		return "", nil, err
	}
	if err := CheckMFA(requireMFA, claims); err != nil {
		auditCtx.FailureReason = "mfa required for administrative role"
		s.recordLoginAudit(ctx, false, auditCtx)
		s.noteLockoutFailure(ctx, lockKey, auditCtx)
		return "", nil, err
	}
	policies := PoliciesForRole(role)
	if s.roles != nil {
		policies = s.roles.PoliciesForRole(ctx, role)
	}
	ttl := OIDCTTL(oidcCfg, s.oidcTTL)
	nhiID := domainauth.NHIKey(domainauth.IdentityTypeOIDC, "", "", subject)
	if s.nhi != nil {
		revoked, err := s.nhi.IsRevoked(ctx, nhiID)
		if err != nil {
			return "", nil, common.Wrap(common.ErrCodeUnavailable, "identity check failed", err)
		}
		if revoked {
			return "", nil, common.New(common.ErrCodeForbidden, "machine identity revoked")
		}
		_ = s.nhi.UpsertFromLogin(ctx, &domainauth.MachineIdentity{
			ID:        nhiID,
			Type:      domainauth.IdentityTypeOIDC,
			BoundName: subject,
			Policies:  policies,
			MaxTTL:    int64(ttl.Seconds()),
		})
	}
	subjectLabel := OIDCSubjectLabel(oidcCfg.Issuer, subject)
	if s.lockout != nil {
		s.lockout.RecordSuccess(lockKey)
	}
	s.recordLoginAudit(ctx, true, auditCtx)
	maxAt := time.Now().UTC().Add(ttl)
	return s.tokens.Create(ctx, subjectLabel, policies, ttl, true, maxAt)
}

func (s *Service) validateKubernetesJWT(ctx context.Context, role, jwtToken string) (ServiceAccountIdentity, string, error) {
	if s.k8s.TokenReviewer != nil {
		review, err := s.k8s.TokenReviewer.Review(ctx, jwtToken)
		if err != nil {
			return ServiceAccountIdentity{}, "", common.Wrap(common.ErrCodeUnauthorized, "token review failed", err)
		}
		if review == nil || !review.Authenticated {
			return ServiceAccountIdentity{}, "", common.New(common.ErrCodeUnauthorized, "kubernetes token not authenticated")
		}
		id := ServiceAccountIdentity{
			Namespace: review.Namespace,
			Name:      review.ServiceAccountName,
			Username:  review.Username,
		}
		if id.Namespace == "" || id.Name == "" {
			if parsed, ok := ParseServiceAccountUsername(review.Username); ok {
				id = parsed
			}
		}
		subject := review.Username
		if subject == "" {
			subject = fmt.Sprintf("system:serviceaccount:%s:%s", id.Namespace, id.Name)
		}
		return id, subject, nil
	}

	if s.k8s.RaftEnabled {
		return ServiceAccountIdentity{}, "", common.New(common.ErrCodeUnauthorized, "kubernetes token review required in production")
	}

	if s.k8s.InsecureDev {
		return parseUnverifiedKubernetesJWT(jwtToken, role)
	}

	if len(s.jwtSecret) > 0 {
		parsed, err := jwt.Parse(jwtToken, func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return s.jwtSecret, nil
		})
		if err != nil {
			return ServiceAccountIdentity{}, "", common.Wrap(common.ErrCodeUnauthorized, "invalid kubernetes jwt", err)
		}
		claims, ok := parsed.Claims.(jwt.MapClaims)
		if !ok || !parsed.Valid {
			return ServiceAccountIdentity{}, "", common.New(common.ErrCodeUnauthorized, "invalid kubernetes jwt claims")
		}
		return identityFromJWTClaims(claims, role)
	}

	return ServiceAccountIdentity{}, "", common.New(common.ErrCodeUnauthorized, "kubernetes authentication not configured")
}

func parseUnverifiedKubernetesJWT(jwtToken, role string) (ServiceAccountIdentity, string, error) {
	parsed, _, err := jwt.NewParser().ParseUnverified(jwtToken, jwt.MapClaims{})
	if err != nil {
		return ServiceAccountIdentity{}, "", common.Wrap(common.ErrCodeUnauthorized, "invalid kubernetes jwt", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return ServiceAccountIdentity{}, "", common.New(common.ErrCodeUnauthorized, "invalid kubernetes jwt claims")
	}
	return identityFromJWTClaims(claims, role)
}

func identityFromJWTClaims(claims jwt.MapClaims, role string) (ServiceAccountIdentity, string, error) {
	subject, _ := claims["sub"].(string)
	if subject == "" {
		return ServiceAccountIdentity{}, "", common.New(common.ErrCodeUnauthorized, "kubernetes jwt subject is required")
	}
	id, ok := ParseServiceAccountUsername(subject)
	if !ok {
		return ServiceAccountIdentity{}, "", common.New(common.ErrCodeUnauthorized, "kubernetes jwt subject must be a service account")
	}
	if subject == role {
		subject = fmt.Sprintf("system:serviceaccount:%s:%s", id.Namespace, id.Name)
	}
	return id, subject, nil
}

// Authorize checks RBAC for a principal.
func (s *Service) Authorize(ctx context.Context, principal Principal, resource, action string) error {
	if !ActionAllowedForPrincipal(principal, action) {
		return common.New(common.ErrCodeForbidden, "action not allowed for agent token")
	}
	if strings.HasPrefix(resource, "secrets/kv/") && !KVPathAllowedForPrincipal(principal, resource) {
		return common.New(common.ErrCodeForbidden, "path outside agent prefix")
	}
	if err := s.syncRBAC(ctx); err != nil {
		return err
	}
	req := RequestContext{Resource: resource, Action: action, AgentID: principal.AgentID}
	if existing, ok := RequestContextFromContext(ctx); ok {
		req = existing
	}
	req.Resource = resource
	req.Action = action
	req.AgentID = principal.AgentID
	if !s.rbac.Authorize(principal.Policies, resource, action, req) {
		return common.New(common.ErrCodeForbidden, "access denied")
	}
	return nil
}

// RBAC exposes the policy engine for administrative operations.
func (s *Service) RBAC() *RBAC {
	return s.rbac
}

// Capabilities returns allowed capabilities for a principal.
func (s *Service) Capabilities(principal Principal) []string {
	return s.rbac.Capabilities(principal.Policies)
}

// MaxClientTokenTTL is the hard cap for admin-created tokens (defense in depth).
const MaxClientTokenTTL = 30 * 24 * time.Hour

// CreateToken issues a scoped client token (admin).
func (s *Service) CreateToken(ctx context.Context, subject string, policies []string, ttl time.Duration, renewable bool) (string, *TokenRecord, error) {
	if subject == "" {
		subject = "token"
	}
	if len(policies) == 0 {
		return "", nil, common.New(common.ErrCodeValidation, "policies are required")
	}
	if ttl > MaxClientTokenTTL {
		ttl = MaxClientTokenTTL
	}
	// TokenStore.Create applies its default when ttl <= 0.
	return s.tokens.Create(ctx, subject, policies, ttl, renewable, time.Time{})
}

// RenewToken extends the caller token TTL.
func (s *Service) RenewToken(ctx context.Context, token string, increment time.Duration) (*TokenRecord, error) {
	if increment > MaxClientTokenTTL {
		increment = MaxClientTokenTTL
	}
	return s.tokens.Renew(ctx, token, increment)
}

// RevokeToken invalidates the caller token and cascades lease / cubbyhole cleanup.
func (s *Service) RevokeToken(ctx context.Context, token string) error {
	id := hashToken(token)
	if err := s.tokens.Revoke(ctx, token); err != nil {
		return err
	}
	if s.leaseCascade != nil {
		_, _ = s.leaseCascade.RevokeByTokenID(ctx, id)
	}
	if s.tokenCleaner != nil {
		_ = s.tokenCleaner.WipeToken(ctx, id)
	}
	return nil
}

// SetLeaseCascade wires lease cascade on token revoke (M-LEASE-1).
func (s *Service) SetLeaseCascade(c LeaseCascade) {
	if s != nil {
		s.leaseCascade = c
	}
}

// SetTokenCleaner wires cubbyhole wipe on token revoke (M-WRAP-1).
func (s *Service) SetTokenCleaner(c TokenCleaner) {
	if s != nil {
		s.tokenCleaner = c
	}
}
