package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubenexis/knxvault/internal/repository"
)

// RevocationRepository persists revoked certificate serials.
type RevocationRepository struct {
	pool *pgxpool.Pool
}

// NewRevocationRepository constructs a RevocationRepository.
func NewRevocationRepository(pool *pgxpool.Pool) *RevocationRepository {
	return &RevocationRepository{pool: pool}
}

// Revoke records a revoked certificate serial.
func (r *RevocationRepository) Revoke(ctx context.Context, cert *repository.RevokedCertificate) error {
	const q = `
INSERT INTO revoked_certificates (serial, ca_id, revoked_at, reason)
VALUES ($1, $2, $3, $4)
ON CONFLICT (serial) DO NOTHING
`
	_, err := r.pool.Exec(ctx, q, cert.Serial, cert.CAID, cert.RevokedAt, cert.Reason)
	if err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}
	return nil
}

// IsRevoked reports whether a serial is revoked.
func (r *RevocationRepository) IsRevoked(ctx context.Context, serial string) (bool, error) {
	const q = `SELECT EXISTS(SELECT 1 FROM revoked_certificates WHERE serial = $1)`
	var exists bool
	if err := r.pool.QueryRow(ctx, q, serial).Scan(&exists); err != nil {
		return false, fmt.Errorf("check revoked serial: %w", err)
	}
	return exists, nil
}

// ListByCA returns revoked certificates for a CA.
func (r *RevocationRepository) ListByCA(ctx context.Context, caID uuid.UUID) ([]*repository.RevokedCertificate, error) {
	const q = `
SELECT serial, ca_id, revoked_at, reason
FROM revoked_certificates
WHERE ca_id = $1
ORDER BY revoked_at ASC
`
	rows, err := r.pool.Query(ctx, q, caID)
	if err != nil {
		return nil, fmt.Errorf("list revoked certificates: %w", err)
	}
	defer rows.Close()

	var out []*repository.RevokedCertificate
	for rows.Next() {
		var cert repository.RevokedCertificate
		if err := rows.Scan(&cert.Serial, &cert.CAID, &cert.RevokedAt, &cert.Reason); err != nil {
			return nil, fmt.Errorf("scan revoked certificate: %w", err)
		}
		out = append(out, &cert)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list revoked certificates rows: %w", err)
	}
	return out, nil
}
