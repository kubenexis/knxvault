// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// TokenRepository is an in-memory client token store.
type TokenRepository struct {
	mu     sync.Mutex
	tokens map[string]*domainauth.ClientToken
}

// NewTokenRepository constructs an empty TokenRepository.
func NewTokenRepository() *TokenRepository {
	return &TokenRepository{tokens: make(map[string]*domainauth.ClientToken)}
}

// Save stores or replaces a token record keyed by ID (token hash).
func (r *TokenRepository) Save(_ context.Context, token *domainauth.ClientToken) error {
	if token == nil || token.ID == "" {
		return common.New(common.ErrCodeValidation, "token id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *token
	r.tokens[token.ID] = &stored
	return nil
}

// Get returns a token by hash ID.
func (r *TokenRepository) Get(_ context.Context, id string) (*domainauth.ClientToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	token, ok := r.tokens[id]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "token not found")
	}
	copy := *token
	return &copy, nil
}

// Revoke marks a token revoked.
func (r *TokenRepository) Revoke(_ context.Context, id string, revokedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	token, ok := r.tokens[id]
	if !ok {
		return common.New(common.ErrCodeNotFound, "token not found")
	}
	token.Revoked = true
	token.ExpiresAt = revokedAt
	return nil
}

// List returns all token records sorted by ID.
func (r *TokenRepository) List(_ context.Context) ([]*domainauth.ClientToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domainauth.ClientToken, 0, len(r.tokens))
	for _, token := range r.tokens {
		copy := *token
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListExpired returns non-revoked tokens expired before the given time.
func (r *TokenRepository) ListExpired(_ context.Context, before time.Time, limit int) ([]*domainauth.ClientToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	var out []*domainauth.ClientToken
	for _, token := range r.tokens {
		if token.Revoked || !token.ExpiresAt.Before(before) {
			continue
		}
		copy := *token
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Clear removes all tokens.
func (r *TokenRepository) Clear(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens = make(map[string]*domainauth.ClientToken)
	return nil
}
