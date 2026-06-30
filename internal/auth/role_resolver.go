package auth

import (
	"context"

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
	if r.roles != nil {
		if stored, err := r.roles.Get(ctx, role); err == nil && len(stored.Policies) > 0 {
			return stored.Policies
		}
	}
	return PoliciesForRole(role)
}
