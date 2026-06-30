package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/pki"
)

// CARepository persists CAs in PostgreSQL.
type CARepository struct {
	pool *pgxpool.Pool
}

// NewCARepository constructs a CARepository.
func NewCARepository(pool *pgxpool.Pool) *CARepository {
	return &CARepository{pool: pool}
}

// Save inserts or updates a CA record.
func (r *CARepository) Save(ctx context.Context, ca *pki.CA) error {
	if err := ca.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid ca", err)
	}

	const q = `
INSERT INTO cas (
    id, parent_id, name, type, cert_pem, privkey_enc, dek_enc, serial, status, created_at, expires_at, crl_next_update
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)
ON CONFLICT (id) DO UPDATE SET
    parent_id = EXCLUDED.parent_id,
    name = EXCLUDED.name,
    type = EXCLUDED.type,
    cert_pem = EXCLUDED.cert_pem,
    privkey_enc = EXCLUDED.privkey_enc,
    dek_enc = EXCLUDED.dek_enc,
    serial = EXCLUDED.serial,
    status = EXCLUDED.status,
    expires_at = EXCLUDED.expires_at,
    crl_next_update = EXCLUDED.crl_next_update
`

	_, err := r.pool.Exec(ctx, q,
		ca.ID,
		ca.ParentID,
		ca.Name,
		string(ca.Type),
		ca.CertPEM,
		ca.PrivateKeyEnc,
		ca.DEKEnc,
		ca.Serial,
		string(ca.Status),
		ca.CreatedAt,
		ca.ExpiresAt,
		ca.CRLNextUpdate,
	)
	if err != nil {
		return fmt.Errorf("save ca: %w", err)
	}
	return nil
}

// GetByID returns a CA by primary key.
func (r *CARepository) GetByID(ctx context.Context, id uuid.UUID) (*pki.CA, error) {
	const q = `
SELECT id, parent_id, name, type, cert_pem, privkey_enc, dek_enc, serial, status, created_at, expires_at, crl_next_update
FROM cas WHERE id = $1
`
	return r.scanOne(ctx, q, id)
}

// GetByName returns a CA by unique name.
func (r *CARepository) GetByName(ctx context.Context, name string) (*pki.CA, error) {
	const q = `
SELECT id, parent_id, name, type, cert_pem, privkey_enc, dek_enc, serial, status, created_at, expires_at, crl_next_update
FROM cas WHERE name = $1
`
	return r.scanOne(ctx, q, name)
}

// List returns all CAs ordered by creation time.
func (r *CARepository) List(ctx context.Context) ([]*pki.CA, error) {
	const q = `
SELECT id, parent_id, name, type, cert_pem, privkey_enc, dek_enc, serial, status, created_at, expires_at, crl_next_update
FROM cas ORDER BY created_at ASC
`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list cas: %w", err)
	}
	defer rows.Close()

	var out []*pki.CA
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ca)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list cas rows: %w", err)
	}
	return out, nil
}

func (r *CARepository) scanOne(ctx context.Context, query string, arg any) (*pki.CA, error) {
	row := r.pool.QueryRow(ctx, query, arg)
	ca, err := scanCA(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, common.New(common.ErrCodeNotFound, "ca not found")
		}
		return nil, err
	}
	return ca, nil
}

type caScanner interface {
	Scan(dest ...any) error
}

func scanCA(row caScanner) (*pki.CA, error) {
	var (
		ca       pki.CA
		caType   string
		status   string
		parentID *uuid.UUID
	)

	if err := row.Scan(
		&ca.ID,
		&parentID,
		&ca.Name,
		&caType,
		&ca.CertPEM,
		&ca.PrivateKeyEnc,
		&ca.DEKEnc,
		&ca.Serial,
		&status,
		&ca.CreatedAt,
		&ca.ExpiresAt,
		&ca.CRLNextUpdate,
	); err != nil {
		return nil, fmt.Errorf("scan ca: %w", err)
	}

	ca.ParentID = parentID
	ca.Type = pki.CAType(caType)
	ca.Status = pki.CAStatus(status)
	return &ca, nil
}
