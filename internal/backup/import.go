package backup

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/repository"
)

// Restore imports a snapshot into repositories.
func Restore(ctx context.Context, repos Repos, snapshot *Snapshot) error {
	if err := ValidateSnapshot(snapshot); err != nil {
		return err
	}
	if repos.CA == nil || repos.Secret == nil {
		return fmt.Errorf("backup repositories not configured")
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
			if err := repos.Policy.Save(ctx, policyToDomain(rec)); err != nil {
				return fmt.Errorf("restore policy %s: %w", rec.Name, err)
			}
		}
	}

	if repos.Role != nil {
		for _, rec := range snapshot.Roles {
			if err := repos.Role.Save(ctx, roleToDomain(rec)); err != nil {
				return fmt.Errorf("restore role %s: %w", rec.Name, err)
			}
		}
	}

	if repos.PKIRole != nil {
		for _, rec := range snapshot.PKIRoles {
			if err := repos.PKIRole.Save(ctx, pkiRoleToDomain(rec)); err != nil {
				return fmt.Errorf("restore pki role %s: %w", rec.Name, err)
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
	caNames := make(map[string]struct{})
	for _, ca := range snapshot.CAs {
		if ca.ParentID != nil {
			if _, ok := seen[*ca.ParentID]; !ok {
				return fmt.Errorf("ca %s references unknown parent", ca.Name)
			}
		}
		caNames[ca.Name] = struct{}{}
	}
	for _, role := range snapshot.PKIRoles {
		if role.Name == "" {
			return fmt.Errorf("pki role name is required")
		}
		if role.CAName == "" {
			return fmt.Errorf("pki role %s ca_name is required", role.Name)
		}
		if _, ok := caNames[role.CAName]; !ok {
			return fmt.Errorf("pki role %s references unknown ca %s", role.Name, role.CAName)
		}
	}
	return nil
}
