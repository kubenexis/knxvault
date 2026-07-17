// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestW82_ManagedSQLNormalizesEvasion(t *testing.T) {
	bad := []string{
		`GRANT  ALL PRIVILEGES ON DATABASE app TO "{{username}}";`,
		`GRANT /*x*/ ALL ON SCHEMA public TO "{{username}}";`,
		`CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}' ROLE admin;`,
		`CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}' ADMIN admin;`,
		`CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}' IN  ROLE admin;`,
		`CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}' IN GROUP ops;`,
	}
	for _, s := range bad {
		if err := secrets.ValidateManagedSQLStatements([]string{s}); err == nil {
			t.Fatalf("expected deny for %q", s)
		}
	}
	ok := `CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`
	if err := secrets.ValidateManagedSQLStatements([]string{ok}); err != nil {
		t.Fatal(err)
	}
}

func TestW83_ManagedSQLDeniesBareRoleGrant(t *testing.T) {
	bad := []string{
		`GRANT some_privileged_role TO "{{username}}";`,
		`GRANT pg_read_server_files TO "{{username}}";`,
		`GRANT pg_write_server_files TO "{{username}}";`,
	}
	for _, s := range bad {
		if err := secrets.ValidateManagedSQLStatements([]string{s}); err == nil {
			t.Fatalf("expected deny for %q", s)
		}
	}
	ok := `GRANT SELECT ON TABLE app.orders TO "{{username}}";`
	if err := secrets.ValidateManagedSQLStatements([]string{ok}); err != nil {
		t.Fatal(err)
	}
}
