package backup

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/repository"
)

// Restore imports a snapshot into repositories, replacing existing state.
func Restore(ctx context.Context, repos Repos, snapshot *Snapshot) error {
	if err := ValidateSnapshot(snapshot); err != nil {
		return err
	}
	if repos.CA == nil || repos.Secret == nil {
		return fmt.Errorf("backup repositories not configured")
	}
	if err := ClearRepos(ctx, repos); err != nil {
		return fmt.Errorf("clear repositories: %w", err)
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

	if repos.SSHRole != nil {
		for _, rec := range snapshot.SSHRoles {
			if err := repos.SSHRole.Save(ctx, sshRoleToDomain(rec)); err != nil {
				return fmt.Errorf("restore ssh role %s: %w", rec.Name, err)
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

	if repos.Token != nil {
		for _, rec := range snapshot.Tokens {
			if err := repos.Token.Save(ctx, tokenToDomain(rec)); err != nil {
				return fmt.Errorf("restore token %s: %w", rec.ID, err)
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

// ValidateSnapshot performs structural validation before restore.
func ValidateSnapshot(snapshot *Snapshot) error {
	if snapshot == nil {
		return fmt.Errorf("snapshot is required")
	}
	if snapshot.Version != formatVersion {
		return fmt.Errorf("unsupported backup version %d", snapshot.Version)
	}
	seen := make(map[uuid.UUID]struct{})
	caNames := make(map[string]struct{})
	for _, ca := range snapshot.CAs {
		if ca.ID == uuid.Nil {
			return fmt.Errorf("ca id is required")
		}
		if _, dup := seen[ca.ID]; dup {
			return fmt.Errorf("duplicate ca id %s", ca.ID)
		}
		seen[ca.ID] = struct{}{}
		if ca.Name == "" {
			return fmt.Errorf("ca name is required")
		}
		if _, dup := caNames[ca.Name]; dup {
			return fmt.Errorf("duplicate ca name %s", ca.Name)
		}
		caNames[ca.Name] = struct{}{}
	}
	for _, ca := range snapshot.CAs {
		if ca.ParentID != nil {
			if _, ok := seen[*ca.ParentID]; !ok {
				return fmt.Errorf("ca %s references unknown parent", ca.Name)
			}
		}
	}
	policyNames := make(map[string]struct{})
	for _, policy := range snapshot.Policies {
		if policy.Name == "" {
			return fmt.Errorf("policy name is required")
		}
		policyNames[policy.Name] = struct{}{}
	}
	for _, role := range snapshot.Roles {
		if role.Name == "" {
			return fmt.Errorf("role name is required")
		}
		for _, policy := range role.Policies {
			if _, ok := policyNames[policy]; !ok {
				return fmt.Errorf("role %s references unknown policy %s", role.Name, policy)
			}
		}
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
	issuedSerials := make(map[string]struct{})
	for _, cert := range snapshot.Issued {
		if cert.CAID == uuid.Nil {
			return fmt.Errorf("issued cert %s ca_id is required", cert.Serial)
		}
		if _, ok := seen[cert.CAID]; !ok {
			return fmt.Errorf("issued cert %s references unknown ca", cert.Serial)
		}
		key := cert.CAID.String() + ":" + cert.Serial
		if _, dup := issuedSerials[key]; dup {
			return fmt.Errorf("duplicate issued cert serial %s", cert.Serial)
		}
		issuedSerials[key] = struct{}{}
	}
	if err := validateAuditRecords(snapshot.Audit); err != nil {
		return err
	}
	return nil
}

func validateAuditRecords(records []AuditRecord) error {
	if len(records) == 0 {
		return nil
	}
	hasHash := false
	for _, rec := range records {
		if rec.Hash != "" {
			hasHash = true
			break
		}
	}
	if !hasHash {
		return nil
	}
	chain := make([]auditsvc.Record, len(records))
	for i, rec := range records {
		chain[i] = auditsvc.Record{
			Timestamp: rec.Timestamp,
			Actor:     rec.Actor,
			Action:    rec.Action,
			Resource:  rec.Resource,
			Status:    rec.Status,
			Details:   rec.Details,
			Hash:      rec.Hash,
		}
	}
	if err := auditsvc.ValidateRecordChain(chain); err != nil {
		return fmt.Errorf("audit chain: %w", err)
	}
	return nil
}
