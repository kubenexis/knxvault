package secrets_test

import (
	"testing"

	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestValidateDatabaseRoleConfigRejectsSecrets(t *testing.T) {
	cases := []map[string]any{
		{"password": "s3cret"},
		{"connection_url": "mysql://admin:pass@db:3306/app"},
		{"nested": map[string]any{"token": "abc"}},
	}
	for _, cfg := range cases {
		if err := domainsecrets.ValidateDatabaseRoleConfig(cfg); err == nil {
			t.Fatalf("expected error for config %#v", cfg)
		}
	}
}

func TestValidateDatabaseRoleConfigAllowsTuning(t *testing.T) {
	cfg := map[string]any{
		"db_type":       "mysql",
		"database_name": "app",
		"ssl_mode":      "require",
		"host":          "db.internal",
	}
	if err := domainsecrets.ValidateDatabaseRoleConfig(cfg); err != nil {
		t.Fatalf("ValidateDatabaseRoleConfig() = %v", err)
	}
}

func TestValidateExecutionMode(t *testing.T) {
	if err := domainsecrets.ValidateExecutionMode(domainsecrets.ExecutionModeClient); err != nil {
		t.Fatalf("client mode: %v", err)
	}
	if err := domainsecrets.ValidateExecutionMode(domainsecrets.ExecutionModeManaged); err == nil {
		t.Fatal("expected managed mode to be rejected until implemented")
	}
}

func TestValidateAdminCredentialsPath(t *testing.T) {
	if err := domainsecrets.ValidateAdminCredentialsPath("database/admin/prod-db"); err != nil {
		t.Fatalf("valid path: %v", err)
	}
	if err := domainsecrets.ValidateAdminCredentialsPath("../escape"); err == nil {
		t.Fatal("expected rejection for .. path")
	}
}

func TestDatabaseRoleValidateDefaultsClientMode(t *testing.T) {
	role := &domainsecrets.DatabaseRole{
		Name:           "readonly",
		TTLSeconds:     3600,
		UsernamePrefix: "v-",
	}
	if err := role.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if role.ExecutionMode != domainsecrets.ExecutionModeClient {
		t.Fatalf("ExecutionMode = %q, want client", role.ExecutionMode)
	}
}
