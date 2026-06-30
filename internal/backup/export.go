package backup

import (
	"context"
	"fmt"
	"time"

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
			snapshot.Policies = append(snapshot.Policies, policyFromDomain(policy))
		}
	}

	if repos.Role != nil {
		roles, err := repos.Role.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list roles: %w", err)
		}
		for _, role := range roles {
			snapshot.Roles = append(snapshot.Roles, roleFromDomain(role))
		}
	}

	if repos.PKIRole != nil {
		pkiRoles, err := repos.PKIRole.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list pki roles: %w", err)
		}
		for _, role := range pkiRoles {
			snapshot.PKIRoles = append(snapshot.PKIRoles, pkiRoleFromDomain(role))
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

	if repos.Token != nil {
		tokens, err := repos.Token.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list tokens: %w", err)
		}
		for _, token := range tokens {
			snapshot.Tokens = append(snapshot.Tokens, tokenFromDomain(token))
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
