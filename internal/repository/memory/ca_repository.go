// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package memory provides in-memory repository implementations for unit tests.
package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/pki"
)

// CARepository is an in-memory CA store.
type CARepository struct {
	mu   sync.RWMutex
	byID map[uuid.UUID]*pki.CA
}

// NewCARepository constructs an empty CARepository.
func NewCARepository() *CARepository {
	return &CARepository{byID: make(map[uuid.UUID]*pki.CA)}
}

// Save stores a CA.
func (r *CARepository) Save(_ context.Context, ca *pki.CA) error {
	if err := ca.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid ca", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, existing := range r.byID {
		if existing.ID != ca.ID && existing.Name == ca.Name {
			return common.New(common.ErrCodeValidation, "ca name already exists")
		}
	}

	stored := *ca
	r.byID[ca.ID] = &stored
	return nil
}

// GetByID returns a CA by ID.
func (r *CARepository) GetByID(_ context.Context, id uuid.UUID) (*pki.CA, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ca, ok := r.byID[id]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "ca not found")
	}
	stored := *ca
	return &stored, nil
}

// GetByName returns a CA by name.
func (r *CARepository) GetByName(_ context.Context, name string) (*pki.CA, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, ca := range r.byID {
		if ca.Name == name {
			stored := *ca
			return &stored, nil
		}
	}
	return nil, common.New(common.ErrCodeNotFound, "ca not found")
}

// List returns all CAs sorted by created time.
func (r *CARepository) List(_ context.Context) ([]*pki.CA, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*pki.CA, 0, len(r.byID))
	for _, ca := range r.byID {
		stored := *ca
		out = append(out, &stored)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}
