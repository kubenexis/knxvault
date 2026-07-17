// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestW79_ManagedSQLDeniesPrivilegeEscalation(t *testing.T) {
	bad := []string{
		`CREATE ROLE "{{username}}" WITH SUPERUSER LOGIN PASSWORD '{{password}}';`,
		`ALTER ROLE "{{username}}" WITH CREATEDB;`,
		`CREATE USER u WITH REPLICATION PASSWORD '{{password}}';`,
		`ALTER ROLE r WITH BYPASSRLS;`,
	}
	for _, s := range bad {
		if err := secrets.ValidateManagedSQLStatements([]string{s}); err == nil {
			t.Fatalf("expected deny for %q", s)
		}
	}
	ok := []string{`CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`}
	if err := secrets.ValidateManagedSQLStatements(ok); err != nil {
		t.Fatal(err)
	}
}
