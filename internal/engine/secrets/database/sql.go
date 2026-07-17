// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// SQLRunner executes SQL statements against a database.
type SQLRunner interface {
	ExecStatements(ctx context.Context, connectionURL string, statements []string) error
}

// DefaultSQLRunner uses database/sql.
type DefaultSQLRunner struct{}

// ExecStatements opens a connection and runs each statement.
func (DefaultSQLRunner) ExecStatements(ctx context.Context, connectionURL string, statements []string) error {
	if len(statements) == 0 {
		return nil
	}
	dsn, driver, err := parseConnectionURL(connectionURL)
	if err != nil {
		return err
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute statement: %w", err)
		}
	}
	return nil
}

func parseConnectionURL(raw string) (dsn, driver string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("connection_url is required")
	}
	if strings.HasPrefix(raw, "sqlite:") {
		return strings.TrimPrefix(raw, "sqlite:"), "sqlite", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse connection_url: %w", err)
	}
	switch parsed.Scheme {
	case "sqlite", "file":
		path := strings.TrimPrefix(raw, parsed.Scheme+":")
		return path, "sqlite", nil
	case "mysql":
		return raw, "mysql", fmt.Errorf("mysql driver not bundled; use sqlite for tests or client execution mode")
	case "postgres", "postgresql":
		return postgresDSN(parsed), "pgx", nil
	default:
		return "", "", fmt.Errorf("unsupported connection_url scheme %q", parsed.Scheme)
	}
}

func postgresDSN(parsed *url.URL) string {
	if parsed == nil {
		return ""
	}
	clone := *parsed
	if clone.Scheme == "postgresql" {
		clone.Scheme = "postgres"
	}
	return clone.String()
}
