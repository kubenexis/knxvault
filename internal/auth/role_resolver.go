// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"fmt"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/repository"
)

// RepositoryRoleResolver resolves roles from persistent storage.
type RepositoryRoleResolver struct {
	roles repository.RoleRepository
}

// NewRepositoryRoleResolver constructs a role resolver backed by a repository.
func NewRepositoryRoleResolver(roles repository.RoleRepository) *RepositoryRoleResolver {
	return &RepositoryRoleResolver{roles: roles}
}

// PoliciesForRole returns policy names for a role (including policy_groups).
func (r *RepositoryRoleResolver) PoliciesForRole(ctx context.Context, role string) []string {
	stored, err := r.GetRole(ctx, role)
	if err == nil {
		return flattenRolePolicies(stored.Policies, stored.PolicyGroups)
	}
	return PoliciesForRole(role)
}

func flattenRolePolicies(policies, groups []string) []string {
	if len(groups) == 0 {
		return policies
	}
	seen := make(map[string]struct{}, len(policies)+len(groups))
	out := make([]string, 0, len(policies)+len(groups))
	for _, name := range append(append([]string{}, policies...), groups...) {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

// GetStoredRole returns a role persisted in the repository.
func (r *RepositoryRoleResolver) GetStoredRole(ctx context.Context, name string) (*domainauth.Role, error) {
	if r.roles == nil {
		return nil, fmt.Errorf("role not found")
	}
	stored, err := r.roles.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	copy := *stored
	return &copy, nil
}

// GetRole returns a stored role or a default mapping.
func (r *RepositoryRoleResolver) GetRole(ctx context.Context, name string) (*domainauth.Role, error) {
	if stored, err := r.GetStoredRole(ctx, name); err == nil {
		return stored, nil
	}
	policies := PoliciesForRole(name)
	if len(policies) == 0 {
		return nil, fmt.Errorf("role not found")
	}
	return &domainauth.Role{Name: name, Policies: policies}, nil
}
