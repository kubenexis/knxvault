package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/kubenexis/knxvault/internal/domain/audit"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/repository"
)

// AuditRepository is an in-memory audit log store.
type AuditRepository struct {
	mu      sync.Mutex
	entries []*audit.Entry
	nextID  int64
}

// NewAuditRepository constructs an empty AuditRepository.
func NewAuditRepository() *AuditRepository {
	return &AuditRepository{nextID: 1}
}

// Append stores an audit entry.
func (r *AuditRepository) Append(_ context.Context, entry *audit.Entry) error {
	if err := entry.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid audit entry", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	stored := *entry
	stored.ID = r.nextID
	r.nextID++
	r.entries = append(r.entries, &stored)
	entry.ID = stored.ID
	return nil
}

// List returns audit entries newest-first.
func (r *AuditRepository) List(_ context.Context, opts repository.AuditListOptions) ([]*audit.Entry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	filtered := make([]*audit.Entry, 0, len(r.entries))
	for _, entry := range r.entries {
		if opts.Since != nil && entry.Timestamp.Before(*opts.Since) {
			continue
		}
		stored := *entry
		filtered = append(filtered, &stored)
	}

	sort.Slice(filtered, func(i, j int) bool {
		if opts.OrderAsc {
			if filtered[i].Timestamp.Equal(filtered[j].Timestamp) {
				return filtered[i].ID < filtered[j].ID
			}
			return filtered[i].Timestamp.Before(filtered[j].Timestamp)
		}
		if filtered[i].Timestamp.Equal(filtered[j].Timestamp) {
			return filtered[i].ID > filtered[j].ID
		}
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	start := opts.Offset
	if start > len(filtered) {
		return []*audit.Entry{}, nil
	}
	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[start:end], nil
}

// LatestHash returns the hash of the most recent audit entry.
func (r *AuditRepository) LatestHash(_ context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		return "", nil
	}
	return r.entries[len(r.entries)-1].Hash, nil
}
