package secrets

import (
	"fmt"
	"time"
)

// DatabaseRole configures dynamic database credential generation.
type DatabaseRole struct {
	Name                 string
	TTLSeconds           int
	UsernamePrefix       string
	DefaultUsername      string
	CreationStatements   []string
	RevocationStatements []string
	Config               map[string]any
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// Validate checks database role configuration.
func (r *DatabaseRole) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("database role name is required")
	}
	if r.TTLSeconds <= 0 {
		return fmt.Errorf("database role ttl must be positive")
	}
	if r.UsernamePrefix == "" {
		return fmt.Errorf("database role username prefix is required")
	}
	return nil
}
