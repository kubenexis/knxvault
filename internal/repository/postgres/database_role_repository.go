package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

// DatabaseRoleRepository persists database roles in PostgreSQL.
type DatabaseRoleRepository struct {
	pool *pgxpool.Pool
}

// NewDatabaseRoleRepository constructs a DatabaseRoleRepository.
func NewDatabaseRoleRepository(pool *pgxpool.Pool) *DatabaseRoleRepository {
	return &DatabaseRoleRepository{pool: pool}
}

// Save inserts or updates a database role.
func (r *DatabaseRoleRepository) Save(ctx context.Context, role *secrets.DatabaseRole) error {
	if err := role.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid database role", err)
	}

	creationJSON, err := json.Marshal(role.CreationStatements)
	if err != nil {
		return fmt.Errorf("marshal creation statements: %w", err)
	}
	revocationJSON, err := json.Marshal(role.RevocationStatements)
	if err != nil {
		return fmt.Errorf("marshal revocation statements: %w", err)
	}
	config := role.Config
	if config == nil {
		config = map[string]any{}
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	now := time.Now().UTC()
	secrets.NormalizeDatabaseRole(role)

	const q = `
INSERT INTO database_roles (
    name, ttl_seconds, username_prefix, default_username,
    creation_statements, revocation_statements, execution_mode,
    admin_credentials_path, config, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
ON CONFLICT (name) DO UPDATE SET
    ttl_seconds = EXCLUDED.ttl_seconds,
    username_prefix = EXCLUDED.username_prefix,
    default_username = EXCLUDED.default_username,
    creation_statements = EXCLUDED.creation_statements,
    revocation_statements = EXCLUDED.revocation_statements,
    execution_mode = EXCLUDED.execution_mode,
    admin_credentials_path = EXCLUDED.admin_credentials_path,
    config = EXCLUDED.config,
    updated_at = EXCLUDED.updated_at
`
	_, err = r.pool.Exec(ctx, q,
		role.Name,
		role.TTLSeconds,
		role.UsernamePrefix,
		role.DefaultUsername,
		creationJSON,
		revocationJSON,
		role.ExecutionMode,
		role.AdminCredentialsPath,
		configJSON,
		now,
	)
	if err != nil {
		return fmt.Errorf("save database role: %w", err)
	}
	return nil
}

// Get returns a database role by name.
func (r *DatabaseRoleRepository) Get(ctx context.Context, name string) (*secrets.DatabaseRole, error) {
	const q = `
SELECT name, ttl_seconds, username_prefix, default_username,
       creation_statements, revocation_statements, execution_mode,
       admin_credentials_path, config, created_at, updated_at
FROM database_roles WHERE name = $1
`
	row := r.pool.QueryRow(ctx, q, name)
	role, err := scanDatabaseRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, common.New(common.ErrCodeNotFound, "database role not found")
		}
		return nil, err
	}
	return role, nil
}

// List returns all database roles ordered by name.
func (r *DatabaseRoleRepository) List(ctx context.Context) ([]*secrets.DatabaseRole, error) {
	const q = `
SELECT name, ttl_seconds, username_prefix, default_username,
       creation_statements, revocation_statements, execution_mode,
       admin_credentials_path, config, created_at, updated_at
FROM database_roles ORDER BY name ASC
`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list database roles: %w", err)
	}
	defer rows.Close()

	var out []*secrets.DatabaseRole
	for rows.Next() {
		role, err := scanDatabaseRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list database roles rows: %w", err)
	}
	return out, nil
}

// Delete removes a database role by name.
func (r *DatabaseRoleRepository) Delete(ctx context.Context, name string) error {
	const q = `DELETE FROM database_roles WHERE name = $1`
	tag, err := r.pool.Exec(ctx, q, name)
	if err != nil {
		return fmt.Errorf("delete database role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return common.New(common.ErrCodeNotFound, "database role not found")
	}
	return nil
}

type databaseRoleScanner interface {
	Scan(dest ...any) error
}

func scanDatabaseRole(row databaseRoleScanner) (*secrets.DatabaseRole, error) {
	var (
		role           secrets.DatabaseRole
		creationJSON   []byte
		revocationJSON []byte
		configJSON     []byte
	)
	if err := row.Scan(
		&role.Name,
		&role.TTLSeconds,
		&role.UsernamePrefix,
		&role.DefaultUsername,
		&creationJSON,
		&revocationJSON,
		&role.ExecutionMode,
		&role.AdminCredentialsPath,
		&configJSON,
		&role.CreatedAt,
		&role.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("scan database role: %w", err)
	}
	if len(creationJSON) > 0 {
		if err := json.Unmarshal(creationJSON, &role.CreationStatements); err != nil {
			return nil, fmt.Errorf("unmarshal creation statements: %w", err)
		}
	}
	if len(revocationJSON) > 0 {
		if err := json.Unmarshal(revocationJSON, &role.RevocationStatements); err != nil {
			return nil, fmt.Errorf("unmarshal revocation statements: %w", err)
		}
	}
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &role.Config); err != nil {
			return nil, fmt.Errorf("unmarshal config: %w", err)
		}
	}
	if role.Config == nil {
		role.Config = map[string]any{}
	}
	secrets.NormalizeDatabaseRole(&role)
	return &role, nil
}
