// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
)

const (
	dbTypePostgres     = "postgres"
	dbTypePostgreSQL   = "postgresql"
	dbTypeCNPG         = "cnpg"
	privilegeReadonly  = "readonly"
	privilegeReadWrite = "readwrite"
)

// statementContext carries template variables for SQL rendering.
type statementContext struct {
	Username   string
	Password   string
	Database   string
	Schema     string
	Expiration string
}

func applyDBTypeDefaults(role *domainsecrets.DatabaseRole) {
	if role == nil {
		return
	}
	dbType := normalizeDBType(role.Config)
	if !isPostgresFamily(dbType) {
		return
	}
	if len(role.CreationStatements) == 0 {
		priv := privilegeFromConfig(role.Config)
		role.CreationStatements = postgresCreationStatements(priv)
	}
	if len(role.RevocationStatements) == 0 {
		priv := privilegeFromConfig(role.Config)
		role.RevocationStatements = postgresRevocationStatements(priv)
	}
}

func normalizeDBType(config map[string]any) string {
	if config == nil {
		return ""
	}
	raw, _ := config["db_type"].(string)
	return strings.ToLower(strings.TrimSpace(raw))
}

func isPostgresFamily(dbType string) bool {
	switch dbType {
	case dbTypePostgres, dbTypePostgreSQL, dbTypeCNPG:
		return true
	default:
		return false
	}
}

func privilegeFromConfig(config map[string]any) string {
	if config == nil {
		return privilegeReadonly
	}
	raw, _ := config["privilege"].(string)
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case privilegeReadWrite, "rw", "write":
		return privilegeReadWrite
	default:
		return privilegeReadonly
	}
}

func databaseFromConfig(config map[string]any) string {
	if config == nil {
		return "postgres"
	}
	for _, key := range []string{"database_name", "database", "db_name"} {
		if raw, ok := config[key].(string); ok && strings.TrimSpace(raw) != "" {
			return strings.TrimSpace(raw)
		}
	}
	return "postgres"
}

func schemaFromConfig(config map[string]any) string {
	if config == nil {
		return "public"
	}
	if raw, ok := config["schema"].(string); ok && strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw)
	}
	return "public"
}

func sslModeFromConfig(config map[string]any) string {
	if config == nil {
		return "require"
	}
	if raw, ok := config["ssl_mode"].(string); ok && strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw)
	}
	return "require"
}

func postgresCreationStatements(privilege string) []string {
	db := "{{database}}"
	schema := "{{schema}}"
	user := `"{{username}}"`
	switch privilege {
	case privilegeReadWrite:
		return []string{
			fmt.Sprintf(`CREATE ROLE %s WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`, user),
			fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s;", db, user),
			fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s;", schema, user),
			fmt.Sprintf("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %s TO %s;", schema, user),
			fmt.Sprintf("ALTER DEFAULT PRIVILEGES IN SCHEMA %s GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %s;", schema, user),
		}
	default:
		return []string{
			fmt.Sprintf(`CREATE ROLE %s WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`, user),
			fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s;", db, user),
			fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s;", schema, user),
			fmt.Sprintf("GRANT SELECT ON ALL TABLES IN SCHEMA %s TO %s;", schema, user),
			fmt.Sprintf("ALTER DEFAULT PRIVILEGES IN SCHEMA %s GRANT SELECT ON TABLES TO %s;", schema, user),
		}
	}
}

func postgresRevocationStatements(privilege string) []string {
	_ = privilege
	db := "{{database}}"
	schema := "{{schema}}"
	user := `"{{username}}"`
	return []string{
		fmt.Sprintf("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %s FROM %s;", schema, user),
		fmt.Sprintf("REVOKE USAGE ON SCHEMA %s FROM %s;", schema, user),
		fmt.Sprintf("REVOKE CONNECT ON DATABASE %s FROM %s;", db, user),
		fmt.Sprintf("DROP ROLE IF EXISTS %s;", user),
	}
}

func buildStatementContext(role *domainsecrets.DatabaseRole, username, password string, expiresAt time.Time) statementContext {
	// W78-05: username must be a safe identifier (templates wrap with "…").
	// Reject quote/injection characters rather than double-quoting allow-list templates.
	return statementContext{
		Username:   username,
		Password:   escapePostgresLiteral(password),
		Database:   quotePostgresIdent(databaseFromConfig(role.Config)),
		Schema:     quotePostgresIdent(schemaFromConfig(role.Config)),
		Expiration: expiresAt.UTC().Format("2006-01-02 15:04:05-07"),
	}
}

// safePostgresUsername reports whether username is safe to embed in "{{username}}" templates.
func safePostgresUsername(username string) bool {
	if username == "" || len(username) > 63 {
		return false
	}
	for i, r := range username {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			continue
		}
		if i > 0 && r == '-' {
			continue
		}
		return false
	}
	return true
}

func renderStatementsForRole(templates []string, role *domainsecrets.DatabaseRole, username, password string, expiresAt time.Time) []string {
	if len(templates) == 0 {
		return nil
	}
	ctx := buildStatementContext(role, username, password, expiresAt)
	out := make([]string, len(templates))
	for i, tmpl := range templates {
		out[i] = strings.NewReplacer(
			"{{username}}", ctx.Username,
			"{{password}}", ctx.Password,
			"{{name}}", ctx.Username,
			"{{database}}", ctx.Database,
			"{{schema}}", ctx.Schema,
			"{{expiration}}", ctx.Expiration,
		).Replace(tmpl)
	}
	return out
}

func escapePostgresLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func quotePostgresIdent(ident string) string {
	ident = strings.TrimSpace(ident)
	if ident == "" {
		return `""`
	}
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

// BuildConnectionURL assembles a PostgreSQL connection URL from KV admin credential fields.
func BuildConnectionURL(data map[string]any, config map[string]any) (string, error) {
	if raw, ok := data["connection_url"].(string); ok && strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw), nil
	}
	username, _ := data["username"].(string)
	password, _ := data["password"].(string)
	host, _ := data["host"].(string)
	database, _ := data["database"].(string)
	portStr, _ := data["port"].(string)

	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	host = strings.TrimSpace(host)
	database = strings.TrimSpace(database)
	if database == "" {
		database = databaseFromConfig(config)
	}
	if host == "" {
		return "", fmt.Errorf("admin credentials require connection_url or host")
	}
	if username == "" {
		return "", fmt.Errorf("admin credentials require connection_url or username")
	}

	port := 5432
	if portStr != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || parsed <= 0 {
			return "", fmt.Errorf("invalid port %q", portStr)
		}
		port = parsed
	}

	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(username, password),
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   "/" + database,
	}
	q := u.Query()
	q.Set("sslmode", sslModeFromConfig(config))
	u.RawQuery = q.Encode()
	return u.String(), nil
}
