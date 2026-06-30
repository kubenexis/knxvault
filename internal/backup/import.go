package backup

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/repository"
)

// Restore imports a snapshot into repositories, replacing existing state when a pool is provided.
func Restore(ctx context.Context, repos Repos, pool *pgxpool.Pool, snapshot *Snapshot) error {
	if snapshot == nil {
		return fmt.Errorf("snapshot is required")
	}
	if snapshot.Version != formatVersion {
		return fmt.Errorf("unsupported backup version %d", snapshot.Version)
	}
	if repos.CA == nil || repos.Secret == nil {
		return fmt.Errorf("backup repositories not configured")
	}

	if pool != nil {
		if err := truncateState(ctx, pool); err != nil {
			return err
		}
	}

	for _, rec := range sortCAs(snapshot.CAs) {
		if err := repos.CA.Save(ctx, caToDomain(rec)); err != nil {
			return fmt.Errorf("restore ca %s: %w", rec.Name, err)
		}
	}

	for _, rec := range snapshot.Secrets {
		if err := repos.Secret.SaveVersion(ctx, secretToDomain(rec)); err != nil {
			return fmt.Errorf("restore secret %s v%d: %w", rec.Path, rec.Version, err)
		}
	}

	if repos.Revoke != nil {
		for _, rec := range snapshot.Revoked {
			if err := repos.Revoke.Revoke(ctx, &repository.RevokedCertificate{
				Serial:    rec.Serial,
				CAID:      rec.CAID,
				RevokedAt: rec.RevokedAt,
				Reason:    rec.Reason,
			}); err != nil {
				return fmt.Errorf("restore revocation %s: %w", rec.Serial, err)
			}
		}
	}

	if repos.Policy != nil {
		for _, rec := range snapshot.Policies {
			if err := repos.Policy.Save(ctx, &domainauth.Policy{
				Name:       rec.Name,
				Effect:     rec.Effect,
				Resources:  rec.Resources,
				Actions:    rec.Actions,
				Conditions: rec.Conditions,
			}); err != nil {
				return fmt.Errorf("restore policy %s: %w", rec.Name, err)
			}
		}
	}

	if repos.Role != nil {
		for _, rec := range snapshot.Roles {
			if err := repos.Role.Save(ctx, &domainauth.Role{
				Name:     rec.Name,
				Policies: rec.Policies,
			}); err != nil {
				return fmt.Errorf("restore role %s: %w", rec.Name, err)
			}
		}
	}

	if repos.DBRole != nil {
		for _, rec := range snapshot.DBRoles {
			if err := repos.DBRole.Save(ctx, databaseRoleToDomain(rec)); err != nil {
				return fmt.Errorf("restore database role %s: %w", rec.Name, err)
			}
		}
	}

	if repos.Lease != nil {
		for _, rec := range snapshot.Leases {
			if err := repos.Lease.Save(ctx, leaseToDomain(rec)); err != nil {
				return fmt.Errorf("restore lease %s: %w", rec.ID, err)
			}
		}
	}

	if repos.IssuedCert != nil {
		for _, rec := range snapshot.Issued {
			if err := repos.IssuedCert.Save(ctx, issuedToDomain(rec)); err != nil {
				return fmt.Errorf("restore issued cert %s: %w", rec.Serial, err)
			}
		}
	}

	if repos.Audit != nil {
		for _, rec := range snapshot.Audit {
			if err := repos.Audit.Append(ctx, auditToDomain(rec)); err != nil {
				return fmt.Errorf("restore audit entry %s: %w", rec.Action, err)
			}
		}
	}

	return nil
}

func issuedToDomain(rec IssuedCertRecord) *domainpki.IssuedCertificate {
	return &domainpki.IssuedCertificate{
		ID:                rec.ID,
		CAID:              rec.CAID,
		Role:              rec.Role,
		Serial:            rec.Serial,
		CommonName:        rec.CommonName,
		DNSNames:          rec.DNSNames,
		TTLSeconds:        rec.TTLSeconds,
		IssuedAt:          rec.IssuedAt,
		ExpiresAt:         rec.ExpiresAt,
		AutoRenew:         rec.AutoRenew,
		RenewedFromSerial: rec.RenewedFromSerial,
	}
}

func sortCAs(records []CARecord) []CARecord {
	sorted := append([]CARecord(nil), records...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if (sorted[i].ParentID == nil) != (sorted[j].ParentID == nil) {
			return sorted[i].ParentID == nil
		}
		return sorted[i].Name < sorted[j].Name
	})
	return sorted
}

func truncateState(ctx context.Context, pool *pgxpool.Pool) error {
	const q = `
TRUNCATE TABLE
    issued_certificates,
    leases,
    database_roles,
    revoked_certificates,
    secret_versions,
    audit_logs,
    policies,
    roles,
    cas
RESTART IDENTITY CASCADE
`
	_, err := pool.Exec(ctx, q)
	if err != nil {
		return fmt.Errorf("truncate state: %w", err)
	}
	return nil
}

// ValidateSnapshot performs basic structural validation before restore.
func ValidateSnapshot(snapshot *Snapshot) error {
	if snapshot == nil {
		return fmt.Errorf("snapshot is required")
	}
	if snapshot.Version != formatVersion {
		return fmt.Errorf("unsupported backup version %d", snapshot.Version)
	}
	seen := make(map[uuid.UUID]struct{})
	for _, ca := range snapshot.CAs {
		if ca.ID == uuid.Nil {
			return fmt.Errorf("ca id is required")
		}
		seen[ca.ID] = struct{}{}
	}
	for _, ca := range snapshot.CAs {
		if ca.ParentID != nil {
			if _, ok := seen[*ca.ParentID]; !ok {
				return fmt.Errorf("ca %s references unknown parent", ca.Name)
			}
		}
	}
	return nil
}
