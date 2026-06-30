package backup

import (
	"context"
	"fmt"
	"time"

	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
)

// ExportOptions configures snapshot export.
type ExportOptions struct {
	IncludeAudit bool
	AuditLimit   int
}

// Export builds a snapshot from configured repositories.
func Export(ctx context.Context, repos Repos, opts ExportOptions) (*Snapshot, error) {
	if repos.CA == nil || repos.Secret == nil {
		return nil, fmt.Errorf("backup repositories not configured")
	}

	snapshot := &Snapshot{
		Version:   formatVersion,
		CreatedAt: time.Now().UTC(),
	}

	cas, err := repos.CA.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list cas: %w", err)
	}
	for _, ca := range cas {
		snapshot.CAs = append(snapshot.CAs, caFromDomain(ca))
	}

	secretsList, err := repos.Secret.ListByPath(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	for _, sv := range secretsList {
		snapshot.Secrets = append(snapshot.Secrets, secretFromDomain(sv))
	}

	if repos.Revoke != nil {
		for _, ca := range cas {
			revoked, err := repos.Revoke.ListByCA(ctx, ca.ID)
			if err != nil {
				return nil, fmt.Errorf("list revocations: %w", err)
			}
			for _, rec := range revoked {
				snapshot.Revoked = append(snapshot.Revoked, RevokedRecord{
					Serial:    rec.Serial,
					CAID:      rec.CAID,
					RevokedAt: rec.RevokedAt,
					Reason:    rec.Reason,
				})
			}
		}
	}

	if repos.Policy != nil {
		policies, err := repos.Policy.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list policies: %w", err)
		}
		for _, policy := range policies {
			snapshot.Policies = append(snapshot.Policies, PolicyRecord{
				Name:       policy.Name,
				Effect:     policy.Effect,
				Resources:  append([]string(nil), policy.Resources...),
				Actions:    append([]string(nil), policy.Actions...),
				Conditions: policy.Conditions,
			})
		}
	}

	if repos.Role != nil {
		roles, err := repos.Role.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list roles: %w", err)
		}
		for _, role := range roles {
			snapshot.Roles = append(snapshot.Roles, RoleRecord{
				Name:     role.Name,
				Policies: append([]string(nil), role.Policies...),
			})
		}
	}

	if repos.DBRole != nil {
		dbRoles, err := repos.DBRole.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list database roles: %w", err)
		}
		for _, role := range dbRoles {
			snapshot.DBRoles = append(snapshot.DBRoles, databaseRoleFromDomain(role))
		}
	}

	if repos.Lease != nil {
		leases, err := repos.Lease.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list leases: %w", err)
		}
		for _, lease := range leases {
			snapshot.Leases = append(snapshot.Leases, leaseFromDomain(lease))
		}
	}

	if repos.IssuedCert != nil {
		issued, err := repos.IssuedCert.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list issued certificates: %w", err)
		}
		for _, cert := range issued {
			snapshot.Issued = append(snapshot.Issued, issuedFromDomain(cert))
		}
	}

	if opts.IncludeAudit && repos.Audit != nil {
		limit := opts.AuditLimit
		if limit <= 0 {
			limit = 10000
		}
		entries, err := repos.Audit.List(ctx, repository.AuditListOptions{
			Limit:    limit,
			OrderAsc: true,
		})
		if err != nil {
			return nil, fmt.Errorf("list audit logs: %w", err)
		}
		for _, entry := range entries {
			snapshot.Audit = append(snapshot.Audit, auditFromDomain(entry))
		}
	}

	return snapshot, nil
}

func databaseRoleFromDomain(role *secrets.DatabaseRole) DatabaseRoleRecord {
	secrets.NormalizeDatabaseRole(role)
	return DatabaseRoleRecord{
		Name:                 role.Name,
		TTLSeconds:           role.TTLSeconds,
		UsernamePrefix:       role.UsernamePrefix,
		DefaultUsername:      role.DefaultUsername,
		CreationStatements:   append([]string(nil), role.CreationStatements...),
		RevocationStatements: append([]string(nil), role.RevocationStatements...),
		ExecutionMode:        role.ExecutionMode,
		AdminCredentialsPath: role.AdminCredentialsPath,
		Config:               role.Config,
	}
}

func databaseRoleToDomain(rec DatabaseRoleRecord) *secrets.DatabaseRole {
	role := &secrets.DatabaseRole{
		Name:                 rec.Name,
		TTLSeconds:           rec.TTLSeconds,
		UsernamePrefix:       rec.UsernamePrefix,
		DefaultUsername:      rec.DefaultUsername,
		CreationStatements:   rec.CreationStatements,
		RevocationStatements: rec.RevocationStatements,
		ExecutionMode:        rec.ExecutionMode,
		AdminCredentialsPath: rec.AdminCredentialsPath,
		Config:               rec.Config,
	}
	secrets.NormalizeDatabaseRole(role)
	return role
}

func leaseFromDomain(lease *secrets.Lease) LeaseRecord {
	return LeaseRecord{
		ID:         lease.ID,
		Path:       lease.Path,
		RoleName:   lease.RoleName,
		Engine:     lease.Engine,
		TTLSeconds: lease.TTLSeconds,
		CreatedAt:  lease.CreatedAt,
		ExpiresAt:  lease.ExpiresAt,
		RevokedAt:  lease.RevokedAt,
		Renewable:  lease.Renewable,
	}
}

func leaseToDomain(rec LeaseRecord) *secrets.Lease {
	return &secrets.Lease{
		ID:         rec.ID,
		Path:       rec.Path,
		RoleName:   rec.RoleName,
		Engine:     rec.Engine,
		TTLSeconds: rec.TTLSeconds,
		CreatedAt:  rec.CreatedAt,
		ExpiresAt:  rec.ExpiresAt,
		RevokedAt:  rec.RevokedAt,
		Renewable:  rec.Renewable,
	}
}

func issuedFromDomain(cert *domainpki.IssuedCertificate) IssuedCertRecord {
	return IssuedCertRecord{
		ID:                cert.ID,
		CAID:              cert.CAID,
		Role:              cert.Role,
		Serial:            cert.Serial,
		CommonName:        cert.CommonName,
		DNSNames:          append([]string(nil), cert.DNSNames...),
		TTLSeconds:        cert.TTLSeconds,
		IssuedAt:          cert.IssuedAt,
		ExpiresAt:         cert.ExpiresAt,
		AutoRenew:         cert.AutoRenew,
		RenewedFromSerial: cert.RenewedFromSerial,
	}
}
