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

// MachineIdentityRepository is an in-memory NHI store.
type MachineIdentityRepository struct {
	mu   sync.Mutex
	byID map[string]*domainauth.MachineIdentity
}

// NewMachineIdentityRepository constructs an empty repository.
func NewMachineIdentityRepository() *MachineIdentityRepository {
	return &MachineIdentityRepository{byID: make(map[string]*domainauth.MachineIdentity)}
}

// Save stores a machine identity.
func (r *MachineIdentityRepository) Save(_ context.Context, id *domainauth.MachineIdentity) error {
	if err := id.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid machine identity", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *id
	r.byID[id.ID] = &stored
	return nil
}

// Get returns a machine identity by ID.
func (r *MachineIdentityRepository) Get(_ context.Context, id string) (*domainauth.MachineIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.byID[id]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "machine identity not found")
	}
	copy := *rec
	return &copy, nil
}

// List returns all identities sorted by ID.
func (r *MachineIdentityRepository) List(_ context.Context) ([]*domainauth.MachineIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domainauth.MachineIdentity, 0, len(r.byID))
	for _, rec := range r.byID {
		copy := *rec
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Revoke marks an identity revoked.
func (r *MachineIdentityRepository) Revoke(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.byID[id]
	if !ok {
		return common.New(common.ErrCodeNotFound, "machine identity not found")
	}
	rec.Revoked = true
	return nil
}
