// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

// LeaseRepository is an in-memory lease store.
type LeaseRepository struct {
	mu     sync.Mutex
	leases map[string]*secrets.Lease
}

// NewLeaseRepository constructs an empty LeaseRepository.
func NewLeaseRepository() *LeaseRepository {
	return &LeaseRepository{leases: make(map[string]*secrets.Lease)}
}

// Save stores a lease.
func (r *LeaseRepository) Save(_ context.Context, lease *secrets.Lease) error {
	if err := lease.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid lease", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *lease
	r.leases[lease.ID] = &stored
	return nil
}

// Get returns a lease by ID.
func (r *LeaseRepository) Get(_ context.Context, id string) (*secrets.Lease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lease, ok := r.leases[id]
	if !ok {
		return nil, common.New(common.ErrCodeNotFound, "lease not found")
	}
	copy := *lease
	return &copy, nil
}

// List returns all leases.
func (r *LeaseRepository) List(_ context.Context) ([]*secrets.Lease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*secrets.Lease, 0, len(r.leases))
	for _, lease := range r.leases {
		copy := *lease
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListExpired returns active leases expiring before the given time.
func (r *LeaseRepository) ListExpired(_ context.Context, before time.Time, limit int) ([]*secrets.Lease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	var out []*secrets.Lease
	for _, lease := range r.leases {
		if lease.RevokedAt != nil {
			continue
		}
		if lease.ExpiresAt.After(before) {
			continue
		}
		copy := *lease
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ExpiresAt.Before(out[j].ExpiresAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// CountActive returns leases that are not revoked and not expired.
func (r *LeaseRepository) CountActive(_ context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	count := 0
	for _, lease := range r.leases {
		if lease.Active(now) {
			count++
		}
	}
	return count, nil
}

// Revoke marks a lease revoked.
func (r *LeaseRepository) Revoke(_ context.Context, id string, revokedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	lease, ok := r.leases[id]
	if !ok {
		return common.New(common.ErrCodeNotFound, "lease not found")
	}
	lease.RevokedAt = &revokedAt
	return nil
}
