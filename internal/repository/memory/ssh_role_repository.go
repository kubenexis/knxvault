// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

// SSHRoleRepository is an in-memory SSH role store.
type SSHRoleRepository struct {
	mu    sync.Mutex
	roles map[string]*secrets.SSHRole
}

// NewSSHRoleRepository constructs an empty SSHRoleRepository.
func NewSSHRoleRepository() *SSHRoleRepository {
	return &SSHRoleRepository{roles: make(map[string]*secrets.SSHRole)}
}

// Save stores an SSH role.
func (r *SSHRoleRepository) Save(_ context.Context, role *secrets.SSHRole) error {
	if err := role.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid ssh role", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *role
	r.roles[role.Name] = &stored
	return nil
}

// Get returns an SSH role by name.
func (r *SSHRoleRepository) Get(_ context.Context, name string) (*secrets.SSHRole, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	role, ok := r.roles[name]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "ssh role not found")
	}
	copy := *role
	return &copy, nil
}

// List returns all SSH roles sorted by name.
func (r *SSHRoleRepository) List(_ context.Context) ([]*secrets.SSHRole, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*secrets.SSHRole, 0, len(r.roles))
	for _, role := range r.roles {
		copy := *role
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Delete removes an SSH role.
func (r *SSHRoleRepository) Delete(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.roles[name]; !ok {
		return common.New(common.ErrCodeNotFound, "ssh role not found")
	}
	delete(r.roles, name)
	return nil
}
