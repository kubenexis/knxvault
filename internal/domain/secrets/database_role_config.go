package secrets

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	// ExecutionModeClient returns SQL statements; the caller executes them with external admin creds.
	ExecutionModeClient = "client"
	// ExecutionModeManaged connects and executes SQL using admin creds from KV (reserved).
	ExecutionModeManaged = "managed"
)

var (
	bannedConfigKeys = map[string]struct{}{
		"password":               {},
		"passwd":                 {},
		"secret":                 {},
		"token":                  {},
		"api_key":                {},
		"apikey":                 {},
		"credential":             {},
		"credentials":            {},
		"connection_url":         {},
		"connection_string":      {},
		"connectionuri":          {},
		"database_url":           {},
		"dsn":                    {},
		"uri":                    {},
		"url":                    {},
		"private_key":            {},
		"access_key":             {},
		"secret_key":             {},
		"admin_password":         {},
		"admin_credentials":      {},
		"admin_credentials_path": {},
	}

	embeddedCredsPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^:@\s]+:[^@\s]+@`)
	kvPathPattern        = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9/_-]*$`)
)

// NormalizeDatabaseRole applies defaults for optional fields.
func NormalizeDatabaseRole(role *DatabaseRole) {
	if role == nil {
		return
	}
	if strings.TrimSpace(role.ExecutionMode) == "" {
		role.ExecutionMode = ExecutionModeClient
	}
	if role.Config == nil {
		role.Config = map[string]any{}
	}
	role.AdminCredentialsPath = strings.TrimSpace(role.AdminCredentialsPath)
}

// ValidateDatabaseRoleConfig rejects secret material in role config maps.
func ValidateDatabaseRoleConfig(config map[string]any) error {
	return validateConfigValue("config", config)
}

func validateConfigValue(path string, value any) error {
	switch v := value.(type) {
	case map[string]any:
		for key, nested := range v {
			if err := validateConfigKey(path, key); err != nil {
				return err
			}
			if err := validateConfigValue(path+"."+key, nested); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			if err := validateConfigValue(fmt.Sprintf("%s[%d]", path, i), item); err != nil {
				return err
			}
		}
	case string:
		if err := validateConfigString(path, v); err != nil {
			return err
		}
	}
	return nil
}

func validateConfigKey(path, key string) error {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if _, banned := bannedConfigKeys[normalized]; banned {
		return fmt.Errorf("%s: key %q is not allowed in database role config; store credentials in KV and reference via admin_credentials_path", path, key)
	}
	return nil
}

func validateConfigString(path, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	if embeddedCredsPattern.MatchString(trimmed) {
		return fmt.Errorf("%s: value resembles a connection string with embedded credentials", path)
	}
	if parsed, err := url.Parse(trimmed); err == nil && parsed.User != nil {
		if _, passwordSet := parsed.User.Password(); passwordSet {
			return fmt.Errorf("%s: URL contains embedded credentials", path)
		}
	}
	return nil
}

// ValidateExecutionMode checks the execution mode value.
func ValidateExecutionMode(mode string) error {
	switch mode {
	case ExecutionModeClient:
		return nil
	case ExecutionModeManaged:
		return fmt.Errorf("execution mode %q is reserved and not yet supported", mode)
	default:
		return fmt.Errorf("unsupported execution mode %q (use %q)", mode, ExecutionModeClient)
	}
}

// ValidateAdminCredentialsPath checks optional KV path references.
func ValidateAdminCredentialsPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if strings.Contains(path, "..") || strings.HasPrefix(path, "/") {
		return fmt.Errorf("admin_credentials_path must be a relative KV path without .. segments")
	}
	if !kvPathPattern.MatchString(path) {
		return fmt.Errorf("admin_credentials_path %q has invalid characters", path)
	}
	return nil
}
