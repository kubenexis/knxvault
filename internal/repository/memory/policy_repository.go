// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/google/uuid"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// PolicyRepository is an in-memory policy store.
type PolicyRepository struct {
	mu       sync.Mutex
	policies map[string]*domainauth.Policy
}

// NewPolicyRepository constructs an empty PolicyRepository.
func NewPolicyRepository() *PolicyRepository {
	return &PolicyRepository{policies: make(map[string]*domainauth.Policy)}
}

// Save stores a policy.
func (r *PolicyRepository) Save(_ context.Context, policy *domainauth.Policy) error {
	if err := policy.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid policy", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *policy
	if stored.ID == uuid.Nil {
		stored.ID = uuid.New()
	}
	r.policies[policy.Name] = &stored
	policy.ID = stored.ID
	return nil
}

// GetByName returns a policy by name.
func (r *PolicyRepository) GetByName(_ context.Context, name string) (*domainauth.Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	policy, ok := r.policies[name]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "policy not found")
	}
	copy := *policy
	return &copy, nil
}

// List returns all policies sorted by name.
func (r *PolicyRepository) List(_ context.Context) ([]*domainauth.Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domainauth.Policy, 0, len(r.policies))
	for _, policy := range r.policies {
		copy := *policy
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Delete removes a policy.
func (r *PolicyRepository) Delete(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.policies[name]; !ok {
		return common.New(common.ErrCodeNotFound, "policy not found")
	}
	delete(r.policies, name)
	return nil
}
