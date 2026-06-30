package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

// LeaseRepository persists leases in PostgreSQL.
type LeaseRepository struct {
	pool *pgxpool.Pool
}

// NewLeaseRepository constructs a LeaseRepository.
func NewLeaseRepository(pool *pgxpool.Pool) *LeaseRepository {
	return &LeaseRepository{pool: pool}
}

// Save inserts or updates a lease.
func (r *LeaseRepository) Save(ctx context.Context, lease *secrets.Lease) error {
	if err := lease.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid lease", err)
	}

	const q = `
INSERT INTO leases (id, path, role_name, engine, ttl_seconds, created_at, expires_at, revoked_at, renewable)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO UPDATE SET
    path = EXCLUDED.path,
    role_name = EXCLUDED.role_name,
    engine = EXCLUDED.engine,
    ttl_seconds = EXCLUDED.ttl_seconds,
    expires_at = EXCLUDED.expires_at,
    revoked_at = EXCLUDED.revoked_at,
    renewable = EXCLUDED.renewable
`
	_, err := r.pool.Exec(ctx, q,
		lease.ID,
		lease.Path,
		lease.RoleName,
		lease.Engine,
		lease.TTLSeconds,
		lease.CreatedAt,
		lease.ExpiresAt,
		lease.RevokedAt,
		lease.Renewable,
	)
	if err != nil {
		return fmt.Errorf("save lease: %w", err)
	}
	return nil
}

// Get returns a lease by ID.
func (r *LeaseRepository) Get(ctx context.Context, id string) (*secrets.Lease, error) {
	const q = `
SELECT id, path, role_name, engine, ttl_seconds, created_at, expires_at, revoked_at, renewable
FROM leases WHERE id = $1
`
	row := r.pool.QueryRow(ctx, q, id)
	lease, err := scanLease(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, common.New(common.ErrCodeNotFound, "lease not found")
		}
		return nil, err
	}
	return lease, nil
}

// List returns all leases.
func (r *LeaseRepository) List(ctx context.Context) ([]*secrets.Lease, error) {
	const q = `
SELECT id, path, role_name, engine, ttl_seconds, created_at, expires_at, revoked_at, renewable
FROM leases ORDER BY id
`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list leases: %w", err)
	}
	defer rows.Close()

	var out []*secrets.Lease
	for rows.Next() {
		lease, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list leases rows: %w", err)
	}
	return out, nil
}

// ListExpired returns active leases that expired before the given time.
func (r *LeaseRepository) ListExpired(ctx context.Context, before time.Time, limit int) ([]*secrets.Lease, error) {
	if limit <= 0 {
		limit = 100
	}
	const q = `
SELECT id, path, role_name, engine, ttl_seconds, created_at, expires_at, revoked_at, renewable
FROM leases
WHERE revoked_at IS NULL AND expires_at <= $1
ORDER BY expires_at ASC
LIMIT $2
`
	rows, err := r.pool.Query(ctx, q, before, limit)
	if err != nil {
		return nil, fmt.Errorf("list expired leases: %w", err)
	}
	defer rows.Close()

	var out []*secrets.Lease
	for rows.Next() {
		lease, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list expired leases rows: %w", err)
	}
	return out, nil
}

// Revoke marks a lease revoked.
func (r *LeaseRepository) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
	const q = `UPDATE leases SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`
	tag, err := r.pool.Exec(ctx, q, id, revokedAt)
	if err != nil {
		return fmt.Errorf("revoke lease: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return common.New(common.ErrCodeNotFound, "lease not found")
	}
	return nil
}

type leaseScanner interface {
	Scan(dest ...any) error
}

func scanLease(row leaseScanner) (*secrets.Lease, error) {
	var lease secrets.Lease
	if err := row.Scan(
		&lease.ID,
		&lease.Path,
		&lease.RoleName,
		&lease.Engine,
		&lease.TTLSeconds,
		&lease.CreatedAt,
		&lease.ExpiresAt,
		&lease.RevokedAt,
		&lease.Renewable,
	); err != nil {
		return nil, fmt.Errorf("scan lease: %w", err)
	}
	return &lease, nil
}
