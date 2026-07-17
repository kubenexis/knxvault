// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"strings"
	"unicode"
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
	// W79-04: privilege escalation attributes on CREATE/ALTER ROLE|USER
	"superuser",
	"createdb",
	"createrole",
	"replication",
	"bypassrls",
	"with admin option",
	// W80-02 / W81-14 / W82-01: broad grants
	"grant all",
	"grant all privileges",
	"set role",
	"grant create",
	"with grant option",
	"security invoker",
	"security definer",
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
	// W82-01: normalize comments + whitespace before allow/deny matching.
	norm := normalizeManagedSQL(body)
	for _, bad := range managedSQLDenySubstrings {
		if strings.Contains(norm, bad) {
			return fmt.Errorf("disallowed SQL construct %q", strings.TrimSpace(bad))
		}
	}
	if hasRoleMembershipEscalation(norm) {
		return fmt.Errorf("disallowed SQL construct %q", "role membership (IN ROLE/ROLE/ADMIN/IN GROUP)")
	}
	ok := false
	for _, p := range managedSQLAllowPrefixes {
		if strings.HasPrefix(norm, p) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("statement must start with an allowed verb (CREATE/ALTER/DROP ROLE|USER, GRANT, REVOKE, CREATE/DROP TABLE)")
	}
	if strings.Contains(norm, "password") && !strings.Contains(s, "{{") {
		return fmt.Errorf("password clauses must use template placeholders (e.g. {{password}})")
	}
	return nil
}

// hasRoleMembershipEscalation detects PostgreSQL role membership after the role name
// (CREATE ROLE x ROLE parent / IN ROLE / IN GROUP / ADMIN), without false-positive on
// the CREATE ROLE / ALTER ROLE verb itself (W82-01).
func hasRoleMembershipEscalation(norm string) bool {
	rest := norm
	for _, p := range []string{
		"create role ", "alter role ", "drop role ",
		"create user ", "alter user ", "drop user ",
	} {
		if strings.HasPrefix(rest, p) {
			rest = strings.TrimPrefix(rest, p)
			break
		}
	}
	for _, bad := range []string{" in role ", " in group ", " role ", " admin "} {
		if strings.Contains(rest, bad) {
			return true
		}
	}
	// Trailing membership without surrounding spaces edge: "...password 'x' role admin"
	if strings.Contains(rest, " role ") || strings.HasSuffix(rest, " role") {
		return true
	}
	return false
}

// normalizeManagedSQL lowercases, strips SQL comments, and collapses whitespace (W82-01).
func normalizeManagedSQL(s string) string {
	s = stripSQLComments(s)
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func stripSQLComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if i+1 < len(s) && s[i] == '-' && s[i+1] == '-' {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			if i < len(s) {
				b.WriteByte(' ')
			}
			continue
		}
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			i += 2
			for i+1 < len(s) && (s[i] != '*' || s[i+1] != '/') {
				i++
			}
			if i+1 < len(s) {
				i++
			}
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
