package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

// SecretRepository persists secret versions in PostgreSQL.
type SecretRepository struct {
	pool *pgxpool.Pool
}

// NewSecretRepository constructs a SecretRepository.
func NewSecretRepository(pool *pgxpool.Pool) *SecretRepository {
	return &SecretRepository{pool: pool}
}

// SaveVersion inserts a secret version.
func (r *SecretRepository) SaveVersion(ctx context.Context, sv *secrets.SecretVersion) error {
	if err := sv.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid secret version", err)
	}

	const q = `
INSERT INTO secret_versions (
    id, path, version, data_enc, dek_enc, lease_id, ttl_seconds, created_at, expires_at, destroyed
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
`

	_, err := r.pool.Exec(ctx, q,
		sv.ID,
		sv.Path,
		sv.Version,
		sv.DataEnc,
		sv.DEKEnc,
		sv.LeaseID,
		sv.TTLSeconds,
		sv.CreatedAt,
		sv.ExpiresAt,
		sv.Destroyed,
	)
	if err != nil {
		return fmt.Errorf("save secret version: %w", err)
	}
	return nil
}

// GetLatest returns the newest non-destroyed version for path.
func (r *SecretRepository) GetLatest(ctx context.Context, path string) (*secrets.SecretVersion, error) {
	const q = `
SELECT id, path, version, data_enc, dek_enc, lease_id, ttl_seconds, created_at, expires_at, destroyed
FROM secret_versions
WHERE path = $1 AND destroyed = FALSE
ORDER BY version DESC
LIMIT 1
`
	return r.scanOne(ctx, q, path)
}

// GetVersion returns a specific secret version.
func (r *SecretRepository) GetVersion(ctx context.Context, path string, version int) (*secrets.SecretVersion, error) {
	const q = `
SELECT id, path, version, data_enc, dek_enc, lease_id, ttl_seconds, created_at, expires_at, destroyed
FROM secret_versions
WHERE path = $1 AND version = $2
`
	return r.scanOne(ctx, q, path, version)
}

// ListByPath returns all versions whose path starts with pathPrefix.
func (r *SecretRepository) ListByPath(ctx context.Context, pathPrefix string) ([]*secrets.SecretVersion, error) {
	const q = `
SELECT id, path, version, data_enc, dek_enc, lease_id, ttl_seconds, created_at, expires_at, destroyed
FROM secret_versions
WHERE path LIKE $1
ORDER BY path ASC, version ASC
`
	rows, err := r.pool.Query(ctx, q, pathPrefix+"%")
	if err != nil {
		return nil, fmt.Errorf("list secret versions: %w", err)
	}
	defer rows.Close()

	var out []*secrets.SecretVersion
	for rows.Next() {
		sv, err := scanSecretVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list secret versions rows: %w", err)
	}
	return out, nil
}

// NextVersion returns the next version number for path.
func (r *SecretRepository) NextVersion(ctx context.Context, path string) (int, error) {
	const q = `SELECT COALESCE(MAX(version), 0) + 1 FROM secret_versions WHERE path = $1`

	var next int
	if err := r.pool.QueryRow(ctx, q, path).Scan(&next); err != nil {
		return 0, fmt.Errorf("next secret version: %w", err)
	}
	return next, nil
}

func (r *SecretRepository) scanOne(ctx context.Context, query string, args ...any) (*secrets.SecretVersion, error) {
	row := r.pool.QueryRow(ctx, query, args...)
	sv, err := scanSecretVersion(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, common.New(common.ErrCodeNotFound, "secret version not found")
		}
		return nil, err
	}
	return sv, nil
}

type secretScanner interface {
	Scan(dest ...any) error
}

func scanSecretVersion(row secretScanner) (*secrets.SecretVersion, error) {
	var sv secrets.SecretVersion
	if err := row.Scan(
		&sv.ID,
		&sv.Path,
		&sv.Version,
		&sv.DataEnc,
		&sv.DEKEnc,
		&sv.LeaseID,
		&sv.TTLSeconds,
		&sv.CreatedAt,
		&sv.ExpiresAt,
		&sv.Destroyed,
	); err != nil {
		return nil, fmt.Errorf("scan secret version: %w", err)
	}
	return &sv, nil
}
