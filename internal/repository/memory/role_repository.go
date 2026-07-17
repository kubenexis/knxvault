// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"sort"
	"sync"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// RoleRepository is an in-memory role store.
type RoleRepository struct {
	mu    sync.Mutex
	roles map[string]*domainauth.Role
}

// NewRoleRepository constructs an empty RoleRepository.
func NewRoleRepository() *RoleRepository {
	return &RoleRepository{roles: make(map[string]*domainauth.Role)}
}

// Save stores a role.
func (r *RoleRepository) Save(_ context.Context, role *domainauth.Role) error {
	if err := role.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid role", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *role
	r.roles[role.Name] = &stored
	return nil
}

// Get returns a role by name.
func (r *RoleRepository) Get(_ context.Context, name string) (*domainauth.Role, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	role, ok := r.roles[name]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "role not found")
	}
	copy := *role
	return &copy, nil
}

// List returns all roles sorted by name.
func (r *RoleRepository) List(_ context.Context) ([]*domainauth.Role, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domainauth.Role, 0, len(r.roles))
	for _, role := range r.roles {
		copy := *role
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Delete removes a role.
func (r *RoleRepository) Delete(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.roles[name]; !ok {
		return common.New(common.ErrCodeNotFound, "role not found")
	}
	delete(r.roles, name)
	return nil
}
