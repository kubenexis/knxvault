package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/pki"
)

// PKIRoleRepository is an in-memory PKI role store.
type PKIRoleRepository struct {
	mu    sync.RWMutex
	roles map[string]*pki.Role
}

// NewPKIRoleRepository constructs an empty PKIRoleRepository.
func NewPKIRoleRepository() *PKIRoleRepository {
	return &PKIRoleRepository{roles: make(map[string]*pki.Role)}
}

// Save stores a PKI role.
func (r *PKIRoleRepository) Save(_ context.Context, role *pki.Role) error {
	if err := role.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid pki role", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *role
	r.roles[role.Name] = &stored
	return nil
}

// Get returns a PKI role by name.
func (r *PKIRoleRepository) Get(_ context.Context, name string) (*pki.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	role, ok := r.roles[name]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "pki role not found")
	}
	stored := *role
	return &stored, nil
}

// List returns all PKI roles sorted by name.
func (r *PKIRoleRepository) List(_ context.Context) ([]*pki.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*pki.Role, 0, len(r.roles))
	for _, role := range r.roles {
		stored := *role
		out = append(out, &stored)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
