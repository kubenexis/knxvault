package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// RoleRepository persists roles in PostgreSQL.
type RoleRepository struct {
	pool *pgxpool.Pool
}

// NewRoleRepository constructs a RoleRepository.
func NewRoleRepository(pool *pgxpool.Pool) *RoleRepository {
	return &RoleRepository{pool: pool}
}

// Save inserts or updates a role.
func (r *RoleRepository) Save(ctx context.Context, role *domainauth.Role) error {
	if err := role.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid role", err)
	}

	policiesJSON, err := json.Marshal(role.Policies)
	if err != nil {
		return fmt.Errorf("marshal policies: %w", err)
	}

	now := time.Now().UTC()
	const q = `
INSERT INTO roles (name, policies, created_at, updated_at)
VALUES ($1, $2, $3, $3)
ON CONFLICT (name) DO UPDATE SET
    policies = EXCLUDED.policies,
    updated_at = EXCLUDED.updated_at
`
	_, err = r.pool.Exec(ctx, q, role.Name, policiesJSON, now)
	if err != nil {
		return fmt.Errorf("save role: %w", err)
	}
	return nil
}

// Get returns a role by name.
func (r *RoleRepository) Get(ctx context.Context, name string) (*domainauth.Role, error) {
	const q = `SELECT name, policies FROM roles WHERE name = $1`
	row := r.pool.QueryRow(ctx, q, name)
	role, err := scanRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, common.New(common.ErrCodeNotFound, "role not found")
		}
		return nil, err
	}
	return role, nil
}

// List returns all roles ordered by name.
func (r *RoleRepository) List(ctx context.Context) ([]*domainauth.Role, error) {
	const q = `SELECT name, policies FROM roles ORDER BY name ASC`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()

	var out []*domainauth.Role
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list roles rows: %w", err)
	}
	return out, nil
}

// Delete removes a role by name.
func (r *RoleRepository) Delete(ctx context.Context, name string) error {
	const q = `DELETE FROM roles WHERE name = $1`
	tag, err := r.pool.Exec(ctx, q, name)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return common.New(common.ErrCodeNotFound, "role not found")
	}
	return nil
}

type roleScanner interface {
	Scan(dest ...any) error
}

func scanRole(row roleScanner) (*domainauth.Role, error) {
	var (
		role         domainauth.Role
		policiesJSON []byte
	)
	if err := row.Scan(&role.Name, &policiesJSON); err != nil {
		return nil, fmt.Errorf("scan role: %w", err)
	}
	if len(policiesJSON) > 0 {
		if err := json.Unmarshal(policiesJSON, &role.Policies); err != nil {
			return nil, fmt.Errorf("unmarshal policies: %w", err)
		}
	}
	return &role, nil
}
