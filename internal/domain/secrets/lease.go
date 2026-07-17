package secrets

import (
	"fmt"
	"time"
)

// Lease tracks a dynamic secret credential lifecycle (LLD §4.B.2).
type Lease struct {
	ID         string
	Path       string
	RoleName   string
	Engine     string
	TTLSeconds int
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	Renewable  bool
	// TokenID is the hashed client token that issued the lease (cascade revoke).
	TokenID string
	// Metadata is engine-private opaque data (JSON-friendly string map).
	Metadata map[string]string
}

// Validate checks required lease fields.
func (l *Lease) Validate() error {
	if l.ID == "" {
		return fmt.Errorf("lease id is required")
	}
	if l.Path == "" {
		return fmt.Errorf("lease path is required")
	}
	if l.RoleName == "" {
		return fmt.Errorf("lease role is required")
	}
	if l.Engine == "" {
		return fmt.Errorf("lease engine is required")
	}
	if l.TTLSeconds <= 0 {
		return fmt.Errorf("lease ttl must be positive")
	}
	if l.ExpiresAt.IsZero() {
		return fmt.Errorf("lease expires_at is required")
	}
	return nil
}

// Active returns true when the lease is not revoked and not expired.
func (l *Lease) Active(now time.Time) bool {
	if l.RevokedAt != nil {
		return false
	}
	return now.Before(l.ExpiresAt)
}
