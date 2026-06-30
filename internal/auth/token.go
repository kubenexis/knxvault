package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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
	return s.Create(ctx, subject, policies, s.ttl, true)
}

// Create issues a token with explicit TTL and renewability.
func (s *TokenStore) Create(ctx context.Context, subject string, policies []string, ttl time.Duration, renewable bool) (string, *TokenRecord, error) {
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
	record.ExpiresAt = time.Now().UTC().Add(increment)
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

// RegisterRootToken registers a bootstrap token hash.
func (s *TokenStore) RegisterRootToken(ctx context.Context, token string, policies []string) error {
	record := TokenRecord{
		ID:        hashToken(token),
		Subject:   "root",
		Policies:  policies,
		ExpiresAt: time.Now().UTC().Add(365 * 24 * time.Hour),
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

// Service coordinates authentication flows.
type Service struct {
	tokens    *TokenStore
	rbac      *RBAC
	rbacSync  RBACSyncer
	roles     RoleResolver
	jwtSecret []byte
	k8s       K8sLoginOptions
}

// RoleResolver resolves role names to policy names.
type RoleResolver interface {
	PoliciesForRole(ctx context.Context, role string) []string
}

// RoleBindingResolver resolves full role records for SA binding checks.
type RoleBindingResolver interface {
	GetRole(ctx context.Context, name string) (*domainauth.Role, error)
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

// SetK8sLoginOptions configures Kubernetes login validation.
func (s *Service) SetK8sLoginOptions(opts K8sLoginOptions) {
	s.k8s = opts
}

// LoginWithToken authenticates an opaque token.
func (s *Service) LoginWithToken(ctx context.Context, token string) (*TokenRecord, error) {
	return s.tokens.Authenticate(ctx, token)
}

// LoginKubernetes validates a service account JWT and maps it to a role.
func (s *Service) LoginKubernetes(ctx context.Context, role, jwtToken string) (string, *TokenRecord, error) {
	if jwtToken == "" {
		return "", nil, common.New(common.ErrCodeValidation, "jwt is required")
	}
	if role == "" {
		return "", nil, common.New(common.ErrCodeValidation, "role is required")
	}

	identity, subject, err := s.validateKubernetesJWT(ctx, role, jwtToken)
	if err != nil {
		return "", nil, err
	}

	if bindingResolver, ok := s.roles.(RoleBindingResolver); ok {
		storedRole, err := bindingResolver.GetRole(ctx, role)
		if err != nil {
			return "", nil, common.Wrap(common.ErrCodeForbidden, "role not found", err)
		}
		if err := MatchServiceAccountBinding(storedRole, identity); err != nil {
			return "", nil, err
		}
	}

	policies := PoliciesForRole(role)
	if s.roles != nil {
		policies = s.roles.PoliciesForRole(ctx, role)
	}
	return s.tokens.Issue(ctx, subject, policies)
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
	if s.rbacSync != nil {
		_ = s.rbacSync.SyncRBAC(ctx)
	}
	req := RequestContext{Resource: resource, Action: action}
	if existing, ok := RequestContextFromContext(ctx); ok {
		req = existing
	}
	req.Resource = resource
	req.Action = action
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

// CreateToken issues a scoped client token (admin).
func (s *Service) CreateToken(ctx context.Context, subject string, policies []string, ttl time.Duration, renewable bool) (string, *TokenRecord, error) {
	if subject == "" {
		subject = "token"
	}
	if len(policies) == 0 {
		return "", nil, common.New(common.ErrCodeValidation, "policies are required")
	}
	return s.tokens.Create(ctx, subject, policies, ttl, renewable)
}

// RenewToken extends the caller token TTL.
func (s *Service) RenewToken(ctx context.Context, token string, increment time.Duration) (*TokenRecord, error) {
	return s.tokens.Renew(ctx, token, increment)
}

// RevokeToken invalidates the caller token.
func (s *Service) RevokeToken(ctx context.Context, token string) error {
	return s.tokens.Revoke(ctx, token)
}
