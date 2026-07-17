// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"strings"
)

var managedSQLAllowPrefixes = []string{
	"create role",
	"create user",
	"alter role",
	"alter user",
	"alter default privileges",
	"drop role",
	"drop user",
	"grant ",
	"revoke ",
	"create table",
	"drop table",
	"create temporary table",
}

var managedSQLDenySubstrings = []string{
	"drop database",
	"drop schema",
	"truncate ",
	"alter system",
	"copy ",
	"pg_read_file",
	"pg_write_file",
	"lo_import",
	"lo_export",
	";--",
	" union ",
	" into outfile",
	"load_file",
}

// ValidateManagedSQLStatements enforces template-only SQL for managed execution (W50-22).
func ValidateManagedSQLStatements(statements []string) error {
	for i, stmt := range statements {
		if err := validateOneManagedSQL(stmt); err != nil {
			return fmt.Errorf("statement[%d]: %w", i, err)
		}
	}
	return nil
}

func validateOneManagedSQL(stmt string) error {
	s := strings.TrimSpace(stmt)
	if s == "" {
		return fmt.Errorf("empty statement")
	}
	body := strings.TrimSuffix(strings.TrimSpace(s), ";")
	if strings.Contains(body, ";") {
		return fmt.Errorf("stacked SQL statements are not allowed")
	}
	lower := strings.ToLower(body)
	for _, bad := range managedSQLDenySubstrings {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("disallowed SQL construct %q", strings.TrimSpace(bad))
		}
	}
	ok := false
	for _, p := range managedSQLAllowPrefixes {
		if strings.HasPrefix(lower, p) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("statement must start with an allowed verb (CREATE/ALTER/DROP ROLE|USER, GRANT, REVOKE, CREATE/DROP TABLE)")
	}
	if strings.Contains(lower, "password") && !strings.Contains(s, "{{") {
		return fmt.Errorf("password clauses must use template placeholders (e.g. {{password}})")
	}
	return nil
}
