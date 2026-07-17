// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
)

// RotationPolicyRepository is an in-memory rotation policy store.
type RotationPolicyRepository struct {
	mu       sync.Mutex
	policies map[string]*domainsecrets.RotationPolicy
}

// NewRotationPolicyRepository constructs an empty repository.
func NewRotationPolicyRepository() *RotationPolicyRepository {
	return &RotationPolicyRepository{policies: make(map[string]*domainsecrets.RotationPolicy)}
}

// Save stores a rotation policy keyed by path.
func (r *RotationPolicyRepository) Save(_ context.Context, policy *domainsecrets.RotationPolicy) error {
	if err := policy.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid rotation policy", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *policy
	r.policies[policy.Path] = &stored
	return nil
}

// Get returns a policy by path.
func (r *RotationPolicyRepository) Get(_ context.Context, path string) (*domainsecrets.RotationPolicy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.policies[path]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "rotation policy not found")
	}
	copy := *p
	return &copy, nil
}

// List returns all policies sorted by path.
func (r *RotationPolicyRepository) List(_ context.Context) ([]*domainsecrets.RotationPolicy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domainsecrets.RotationPolicy, 0, len(r.policies))
	for _, p := range r.policies {
		copy := *p
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Delete removes a rotation policy.
func (r *RotationPolicyRepository) Delete(_ context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.policies[path]; !ok {
		return common.New(common.ErrCodeNotFound, "rotation policy not found")
	}
	delete(r.policies, path)
	return nil
}
