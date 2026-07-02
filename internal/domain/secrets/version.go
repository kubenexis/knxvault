package secrets

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// SecretVersion is a versioned KV secret record (LLD §4.B.1).
type SecretVersion struct {
	ID         uuid.UUID
	Path       string
	Version    int
	DataEnc    []byte
	DEKEnc     []byte
	LeaseID    *string
	TTLSeconds *int
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	Destroyed  bool
	Labels     map[string]string
}

// Validate checks required secret version fields.
func (s *SecretVersion) Validate() error {
	if s.ID == uuid.Nil {
		return fmt.Errorf("secret id is required")
	}
	if s.Path == "" {
		return fmt.Errorf("secret path is required")
	}
	if s.Version < 1 {
		return fmt.Errorf("secret version must be >= 1")
	}
	if len(s.DataEnc) == 0 || len(s.DEKEnc) == 0 {
		return fmt.Errorf("encrypted payload and dek are required")
	}
	return nil
}
