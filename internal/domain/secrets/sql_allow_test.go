package secrets_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestValidateManagedSQLStatementsAllowList(t *testing.T) {
	ok := []string{
		`CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
		`GRANT CONNECT ON DATABASE {{database}} TO "{{username}}";`,
		`DROP ROLE IF EXISTS "{{username}}";`,
		`CREATE TABLE IF NOT EXISTS vault_users (username TEXT PRIMARY KEY);`,
	}
	if err := secrets.ValidateManagedSQLStatements(ok); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if err := secrets.ValidateManagedSQLStatements([]string{"DROP DATABASE production;"}); err == nil {
		t.Fatal("expected deny drop database")
	}
	if err := secrets.ValidateManagedSQLStatements([]string{"SELECT * FROM users; DROP ROLE x;"}); err == nil {
		t.Fatal("expected deny stacked")
	}
}

func TestDatabaseRoleManagedSQLStrict(t *testing.T) {
	role := &secrets.DatabaseRole{
		Name:                 "m",
		TTLSeconds:           60,
		UsernamePrefix:       "v-",
		ExecutionMode:        secrets.ExecutionModeManaged,
		AdminCredentialsPath: "db/admin",
		CreationStatements:   []string{"DROP DATABASE x;"},
	}
	if err := role.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
	role.CreationStatements = []string{`CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}';`}
	if err := role.Validate(); err != nil {
		t.Fatalf("valid role: %v", err)
	}
}
