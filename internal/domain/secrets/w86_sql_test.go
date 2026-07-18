// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestW86_ValidateManagedSQLDenyCTASAndPublic(t *testing.T) {
	bad := []string{
		"CREATE TABLE dump AS SELECT * FROM secrets",
		"CREATE TABLE t AS (SELECT password FROM users)",
		"GRANT SELECT ON secrets TO PUBLIC",
		`GRANT SELECT ON secrets TO "public"`,
	}
	for _, s := range bad {
		if err := secrets.ValidateManagedSQLStatements([]string{s}); err == nil {
			t.Fatalf("expected deny for %q", s)
		}
	}
	ok := []string{
		"CREATE ROLE {{name}} WITH LOGIN PASSWORD '{{password}}'",
		"GRANT SELECT ON TABLE appdata TO {{name}}",
	}
	if err := secrets.ValidateManagedSQLStatements(ok); err != nil {
		t.Fatalf("allowed statements rejected: %v", err)
	}
}
