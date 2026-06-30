package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

// DatabaseRoleRepository is an in-memory database role store.
type DatabaseRoleRepository struct {
	mu    sync.Mutex
	roles map[string]*secrets.DatabaseRole
}

// NewDatabaseRoleRepository constructs an empty DatabaseRoleRepository.
func NewDatabaseRoleRepository() *DatabaseRoleRepository {
	return &DatabaseRoleRepository{roles: make(map[string]*secrets.DatabaseRole)}
}

// Save stores a database role.
func (r *DatabaseRoleRepository) Save(_ context.Context, role *secrets.DatabaseRole) error {
	if err := role.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid database role", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *role
	r.roles[role.Name] = &stored
	return nil
}

// Get returns a database role by name.
func (r *DatabaseRoleRepository) Get(_ context.Context, name string) (*secrets.DatabaseRole, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	role, ok := r.roles[name]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "database role not found")
	}
	copy := *role
	return &copy, nil
}

// List returns all database roles sorted by name.
func (r *DatabaseRoleRepository) List(_ context.Context) ([]*secrets.DatabaseRole, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*secrets.DatabaseRole, 0, len(r.roles))
	for _, role := range r.roles {
		copy := *role
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Delete removes a database role.
func (r *DatabaseRoleRepository) Delete(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.roles[name]; !ok {
		return common.New(common.ErrCodeNotFound, "database role not found")
	}
	delete(r.roles, name)
	return nil
}
