package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/domain/pki"
)

// IssuedCertRepository persists issued certificates in PostgreSQL.
type IssuedCertRepository struct {
	pool *pgxpool.Pool
}

// NewIssuedCertRepository constructs an IssuedCertRepository.
func NewIssuedCertRepository(pool *pgxpool.Pool) *IssuedCertRepository {
	return &IssuedCertRepository{pool: pool}
}

// Save inserts or updates an issued certificate record.
func (r *IssuedCertRepository) Save(ctx context.Context, cert *pki.IssuedCertificate) error {
	if err := cert.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid issued certificate", err)
	}
	dnsJSON, err := json.Marshal(cert.DNSNames)
	if err != nil {
		return fmt.Errorf("marshal dns names: %w", err)
	}
	const q = `
INSERT INTO issued_certificates (
    id, ca_id, role, serial, common_name, dns_names, ttl_seconds,
    issued_at, expires_at, auto_renew, renewed_from_serial
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (ca_id, serial) DO UPDATE SET
    role = EXCLUDED.role,
    common_name = EXCLUDED.common_name,
    dns_names = EXCLUDED.dns_names,
    ttl_seconds = EXCLUDED.ttl_seconds,
    expires_at = EXCLUDED.expires_at,
    auto_renew = EXCLUDED.auto_renew,
    renewed_from_serial = EXCLUDED.renewed_from_serial
`
	_, err = r.pool.Exec(ctx, q,
		cert.ID,
		cert.CAID,
		cert.Role,
		cert.Serial,
		cert.CommonName,
		dnsJSON,
		cert.TTLSeconds,
		cert.IssuedAt,
		cert.ExpiresAt,
		cert.AutoRenew,
		cert.RenewedFromSerial,
	)
	if err != nil {
		return fmt.Errorf("save issued certificate: %w", err)
	}
	return nil
}

// GetBySerial returns an issued certificate by CA and serial.
func (r *IssuedCertRepository) GetBySerial(ctx context.Context, caID uuid.UUID, serial string) (*pki.IssuedCertificate, error) {
	const q = `
SELECT id, ca_id, role, serial, common_name, dns_names, ttl_seconds,
       issued_at, expires_at, auto_renew, renewed_from_serial
FROM issued_certificates WHERE ca_id = $1 AND serial = $2
`
	row := r.pool.QueryRow(ctx, q, caID, serial)
	cert, err := scanIssuedCert(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, common.New(common.ErrCodeNotFound, "issued certificate not found")
		}
		return nil, err
	}
	return cert, nil
}

// List returns all issued certificate records.
func (r *IssuedCertRepository) List(ctx context.Context) ([]*pki.IssuedCertificate, error) {
	const q = `
SELECT id, ca_id, role, serial, common_name, dns_names, ttl_seconds,
       issued_at, expires_at, auto_renew, renewed_from_serial
FROM issued_certificates ORDER BY ca_id, serial
`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list issued certificates: %w", err)
	}
	defer rows.Close()

	var out []*pki.IssuedCertificate
	for rows.Next() {
		cert, err := scanIssuedCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list issued certificates rows: %w", err)
	}
	return out, nil
}

// ListExpiring returns auto-renew certs expiring before the given time.
func (r *IssuedCertRepository) ListExpiring(ctx context.Context, before time.Time, limit int) ([]*pki.IssuedCertificate, error) {
	if limit <= 0 {
		limit = 100
	}
	const q = `
SELECT id, ca_id, role, serial, common_name, dns_names, ttl_seconds,
       issued_at, expires_at, auto_renew, renewed_from_serial
FROM issued_certificates
WHERE auto_renew = TRUE AND expires_at <= $1
ORDER BY expires_at ASC
LIMIT $2
`
	rows, err := r.pool.Query(ctx, q, before, limit)
	if err != nil {
		return nil, fmt.Errorf("list expiring certificates: %w", err)
	}
	defer rows.Close()

	var out []*pki.IssuedCertificate
	for rows.Next() {
		cert, err := scanIssuedCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list expiring certificates rows: %w", err)
	}
	return out, nil
}

type issuedCertScanner interface {
	Scan(dest ...any) error
}

func scanIssuedCert(row issuedCertScanner) (*pki.IssuedCertificate, error) {
	var (
		cert    pki.IssuedCertificate
		dnsJSON []byte
		renewed *string
	)
	if err := row.Scan(
		&cert.ID,
		&cert.CAID,
		&cert.Role,
		&cert.Serial,
		&cert.CommonName,
		&dnsJSON,
		&cert.TTLSeconds,
		&cert.IssuedAt,
		&cert.ExpiresAt,
		&cert.AutoRenew,
		&renewed,
	); err != nil {
		return nil, fmt.Errorf("scan issued certificate: %w", err)
	}
	if len(dnsJSON) > 0 {
		if err := json.Unmarshal(dnsJSON, &cert.DNSNames); err != nil {
			return nil, fmt.Errorf("unmarshal dns names: %w", err)
		}
	}
	cert.RenewedFromSerial = renewed
	return &cert, nil
}
