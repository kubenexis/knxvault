// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

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
		// W50-22: default strict SQL allow-list for managed statements.
		// Callers that need custom SQL can set Config["sql_strict"]="false" only when explicitly allowed.
		strict := true
		if r.Config != nil {
			if v, ok := r.Config["sql_strict"]; ok {
				switch t := v.(type) {
				case bool:
					strict = t
				case string:
					strict = t != "false" && t != "0"
				}
			}
		}
		if strict {
			if err := ValidateManagedSQLStatements(r.CreationStatements); err != nil {
				return fmt.Errorf("creation_statements: %w", err)
			}
			if len(r.RevocationStatements) > 0 {
				if err := ValidateManagedSQLStatements(r.RevocationStatements); err != nil {
					return fmt.Errorf("revocation_statements: %w", err)
				}
			}
		}
	}
	return nil
}
