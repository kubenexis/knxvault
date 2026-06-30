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

// PoliciesForRole returns policy names for a role.
func (r *RepositoryRoleResolver) PoliciesForRole(ctx context.Context, role string) []string {
	stored, err := r.GetRole(ctx, role)
	if err == nil && len(stored.Policies) > 0 {
		return stored.Policies
	}
	return PoliciesForRole(role)
}

// GetRole returns a stored role or a default mapping.
func (r *RepositoryRoleResolver) GetRole(ctx context.Context, name string) (*domainauth.Role, error) {
	if r.roles != nil {
		if stored, err := r.roles.Get(ctx, name); err == nil {
			copy := *stored
			return &copy, nil
		}
	}
	policies := PoliciesForRole(name)
	if len(policies) == 0 {
		return nil, fmt.Errorf("role not found")
	}
	return &domainauth.Role{Name: name, Policies: policies}, nil
}
