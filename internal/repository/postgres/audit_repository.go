package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubenexis/knxvault/internal/domain/audit"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/repository"
)

// AuditRepository persists audit log entries in PostgreSQL.
type AuditRepository struct {
	pool *pgxpool.Pool
}

// NewAuditRepository constructs an AuditRepository.
func NewAuditRepository(pool *pgxpool.Pool) *AuditRepository {
	return &AuditRepository{pool: pool}
}

// Append inserts an audit entry and assigns its ID.
func (r *AuditRepository) Append(ctx context.Context, entry *audit.Entry) error {
	if err := entry.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid audit entry", err)
	}

	details := entry.Details
	if details == nil {
		details = map[string]any{}
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}

	const q = `
INSERT INTO audit_logs (timestamp, actor, action, resource, status, details, entry_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id
`

	err = r.pool.QueryRow(ctx, q,
		entry.Timestamp,
		entry.Actor,
		entry.Action,
		entry.Resource,
		entry.Status,
		detailsJSON,
		entry.Hash,
	).Scan(&entry.ID)
	if err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

// List returns audit entries newest-first.
func (r *AuditRepository) List(ctx context.Context, opts repository.AuditListOptions) ([]*audit.Entry, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}

	order := "DESC"
	if opts.OrderAsc {
		order = "ASC"
	}
	q := fmt.Sprintf(`
SELECT id, timestamp, actor, action, resource, status, details, entry_hash
FROM audit_logs
WHERE ($1::timestamptz IS NULL OR timestamp >= $1)
ORDER BY timestamp %s, id %s
LIMIT $2 OFFSET $3
`, order, order)

	rows, err := r.pool.Query(ctx, q, opts.Since, limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	defer rows.Close()

	var out []*audit.Entry
	for rows.Next() {
		entry, err := scanAuditEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit entries rows: %w", err)
	}
	return out, nil
}

// LatestHash returns the hash of the most recent audit entry.
func (r *AuditRepository) LatestHash(ctx context.Context) (string, error) {
	const q = `SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1`
	var hash string
	err := r.pool.QueryRow(ctx, q).Scan(&hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("latest audit hash: %w", err)
	}
	return hash, nil
}

type auditScanner interface {
	Scan(dest ...any) error
}

func scanAuditEntry(row auditScanner) (*audit.Entry, error) {
	var (
		entry       audit.Entry
		detailsJSON []byte
	)

	if err := row.Scan(
		&entry.ID,
		&entry.Timestamp,
		&entry.Actor,
		&entry.Action,
		&entry.Resource,
		&entry.Status,
		&detailsJSON,
		&entry.Hash,
	); err != nil {
		return nil, fmt.Errorf("scan audit entry: %w", err)
	}

	if len(detailsJSON) > 0 {
		if err := json.Unmarshal(detailsJSON, &entry.Details); err != nil {
			return nil, fmt.Errorf("unmarshal audit details: %w", err)
		}
	}
	if entry.Details == nil {
		entry.Details = map[string]any{}
	}

	return &entry, nil
}
