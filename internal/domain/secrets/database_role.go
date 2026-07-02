package secrets

import (
	"fmt"
	"time"
)

// DatabaseRole configures dynamic database credential generation.
type DatabaseRole struct {
	Name                 string
	TTLSeconds           int
	DefaultTTL           int
	MaxTTL               int
	Period               int
	Renewable            bool
	MaxLeases            int
	UsernamePrefix       string
	DefaultUsername      string
	CreationStatements   []string
	RevocationStatements []string
	ExecutionMode        string
	AdminCredentialsPath string
	Config               map[string]any
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// Validate checks database role configuration.
func (r *DatabaseRole) Validate() error {
	NormalizeDatabaseRole(r)
	if r.Name == "" {
		return fmt.Errorf("database role name is required")
	}
	if r.TTLSeconds <= 0 {
		return fmt.Errorf("database role ttl must be positive")
	}
	if r.UsernamePrefix == "" {
		return fmt.Errorf("database role username prefix is required")
	}
	if err := ValidateExecutionMode(r.ExecutionMode); err != nil {
		return err
	}
	if err := ValidateAdminCredentialsPath(r.AdminCredentialsPath); err != nil {
		return err
	}
	if err := ValidateDatabaseRoleConfig(r.Config); err != nil {
		return err
	}
	if r.ExecutionMode == ExecutionModeManaged {
		if r.AdminCredentialsPath == "" {
			return fmt.Errorf("admin_credentials_path is required for managed execution mode")
		}
		if len(r.CreationStatements) == 0 {
			return fmt.Errorf("creation_statements are required for managed execution mode")
		}
	}
	return nil
}
