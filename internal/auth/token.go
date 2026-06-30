package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

// TokenRecord is a stored client token.
type TokenRecord struct {
	ID        string
	Subject   string
	Policies  []string
	ExpiresAt time.Time
}

// TokenStore manages in-memory client tokens.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]TokenRecord
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

// Issue creates a new opaque client token.
func (s *TokenStore) Issue(subject string, policies []string) (string, *TokenRecord, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	token := "knxv_" + base64.RawURLEncoding.EncodeToString(raw)
	record := TokenRecord{
		ID:        hashToken(token),
		Subject:   subject,
		Policies:  policies,
		ExpiresAt: time.Now().UTC().Add(s.ttl),
	}

	s.mu.Lock()
	s.tokens[record.ID] = record
	s.mu.Unlock()

	return token, &record, nil
}

// Authenticate validates an opaque client token.
func (s *TokenStore) Authenticate(token string) (*TokenRecord, error) {
	s.mu.RLock()
	record, ok := s.tokens[hashToken(token)]
	s.mu.RUnlock()
	if !ok {
		return nil, common.New(common.ErrCodeUnauthorized, "invalid token")
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		return nil, common.New(common.ErrCodeUnauthorized, "token expired")
	}
	copy := record
	return &copy, nil
}

// RegisterRootToken registers a bootstrap token hash.
func (s *TokenStore) RegisterRootToken(token string, policies []string) {
	record := TokenRecord{
		ID:        hashToken(token),
		Subject:   "root",
		Policies:  policies,
		ExpiresAt: time.Now().UTC().Add(365 * 24 * time.Hour),
	}
	s.mu.Lock()
	s.tokens[record.ID] = record
	s.mu.Unlock()
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Service coordinates authentication flows.
type Service struct {
	tokens    *TokenStore
	rbac      *RBAC
	roles     RoleResolver
	jwtSecret []byte
}

// RoleResolver resolves role names to policy names.
type RoleResolver interface {
	PoliciesForRole(ctx context.Context, role string) []string
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

// LoginWithToken authenticates an opaque token.
func (s *Service) LoginWithToken(_ context.Context, token string) (*TokenRecord, error) {
	return s.tokens.Authenticate(token)
}

// LoginKubernetes validates a service account JWT and maps it to a role.
func (s *Service) LoginKubernetes(ctx context.Context, role, jwtToken string) (string, *TokenRecord, error) {
	if jwtToken == "" {
		return "", nil, common.New(common.ErrCodeValidation, "jwt is required")
	}

	subject := role
	if len(s.jwtSecret) > 0 {
		parsed, err := jwt.Parse(jwtToken, func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return s.jwtSecret, nil
		})
		if err != nil {
			return "", nil, common.Wrap(common.ErrCodeUnauthorized, "invalid kubernetes jwt", err)
		}
		claims, ok := parsed.Claims.(jwt.MapClaims)
		if !ok || !parsed.Valid {
			return "", nil, common.New(common.ErrCodeUnauthorized, "invalid kubernetes jwt claims")
		}
		if sub, ok := claims["sub"].(string); ok && sub != "" {
			subject = sub
		}
	}

	policies := PoliciesForRole(role)
	if s.roles != nil {
		policies = s.roles.PoliciesForRole(ctx, role)
	}
	return s.tokens.Issue(subject, policies)
}

// Authorize checks RBAC for a principal.
func (s *Service) Authorize(ctx context.Context, principal Principal, resource, action string) error {
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
