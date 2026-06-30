// Package migrate provides one-shot storage migration helpers.
package migrate

import (
	"context"
	"fmt"

	"github.com/kubenexis/knxvault/internal/backup"
	postgres "github.com/kubenexis/knxvault/internal/repository/postgres" //nolint:staticcheck // migration source
)

// ExportFromPostgres reads live PostgreSQL state into a portable snapshot.
func ExportFromPostgres(ctx context.Context, databaseURL string, includeAudit bool) (*backup.Snapshot, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("database url is required")
	}
	pool, err := postgres.NewPool(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	defer pool.Close()

	repos := backup.Repos{
		CA:         postgres.NewCARepository(pool),
		Secret:     postgres.NewSecretRepository(pool),
		Audit:      postgres.NewAuditRepository(pool),
		Revoke:     postgres.NewRevocationRepository(pool),
		Lease:      postgres.NewLeaseRepository(pool),
		Policy:     postgres.NewPolicyRepository(pool),
		Role:       postgres.NewRoleRepository(pool),
		DBRole:     postgres.NewDatabaseRoleRepository(pool),
		IssuedCert: postgres.NewIssuedCertRepository(pool),
	}
	return backup.Export(ctx, repos, backup.ExportOptions{IncludeAudit: includeAudit})
}
