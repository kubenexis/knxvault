// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestW80_ManagedSQLDeniesGrantAllAndInRole(t *testing.T) {
	bad := []string{
		`GRANT ALL PRIVILEGES ON DATABASE app TO "{{username}}";`,
		`GRANT ALL ON SCHEMA public TO "{{username}}";`,
		`CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}' IN ROLE admin;`,
		`ALTER ROLE "{{username}}" IN GROUP operators;`,
		`SET ROLE admin;`,
	}
	for _, s := range bad {
		if err := secrets.ValidateManagedSQLStatements([]string{s}); err == nil {
			t.Fatalf("expected deny for %q", s)
		}
	}
	ok := []string{
		`CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
		`GRANT SELECT ON TABLE app.orders TO "{{username}}";`,
		`REVOKE SELECT ON TABLE app.orders FROM "{{username}}";`,
	}
	if err := secrets.ValidateManagedSQLStatements(ok); err != nil {
		t.Fatal(err)
	}
}
