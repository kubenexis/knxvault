package service

import (
	"context"
	"strings"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	sshengine "github.com/kubenexis/knxvault/internal/engine/secrets/ssh"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// LeaseService provides unified lease operations (W42-01–03).
type LeaseService struct {
	leases   repository.LeaseRepository
	database *databaseengine.Engine
	ssh      *sshengine.Engine
	audit    *auditsvc.Service
}

// NewLeaseService constructs a lease service.
func NewLeaseService(
	leases repository.LeaseRepository,
	database *databaseengine.Engine,
	ssh *sshengine.Engine,
	audit *auditsvc.Service,
) *LeaseService {
	return &LeaseService{leases: leases, database: database, ssh: ssh, audit: audit}
}

// LeaseView is engine-agnostic lease metadata.
type LeaseView struct {
	ID         string     `json:"lease_id"`
	Engine     string     `json:"engine"`
	Role       string     `json:"role"`
	Path       string     `json:"path"`
	TTLSeconds int        `json:"ttl_seconds"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Renewable  bool       `json:"renewable"`
	Revoked    bool       `json:"revoked"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// LeaseListFilter filters lease list queries.
type LeaseListFilter struct {
	Engine     string
	Role       string
	Prefix     string
	ActiveOnly bool
	Limit      int
	Offset     int
}

// Get returns lease metadata by ID.
func (s *LeaseService) Get(ctx context.Context, id string) (*LeaseView, error) {
	if s == nil || s.leases == nil {
		return nil, common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	lease, err := s.leases.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	view := toLeaseView(lease)
	audithelper.Record(s.audit, ctx, "lease.lookup", "sys/leases/"+id, nil, map[string]any{"lease_id": id})
	return view, nil
}

// List returns leases matching filters.
func (s *LeaseService) List(ctx context.Context, filter LeaseListFilter) ([]LeaseView, error) {
	if s == nil || s.leases == nil {
		return nil, common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	all, err := s.leases.List(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var out []LeaseView
	for _, lease := range all {
		if filter.Engine != "" && lease.Engine != filter.Engine {
			continue
		}
		if filter.Role != "" && lease.RoleName != filter.Role {
			continue
		}
		if filter.Prefix != "" && !strings.HasPrefix(lease.Path, filter.Prefix) {
			continue
		}
		if filter.ActiveOnly && !lease.Active(now) {
			continue
		}
		out = append(out, *toLeaseView(lease))
	}
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return nil, nil
		}
		out = out[filter.Offset:]
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

// BulkRevokeRequest selects leases to revoke.
type BulkRevokeRequest struct {
	Engine     string
	Role       string
	PathPrefix string
}

// BulkRevokeResult summarizes bulk revocation.
type BulkRevokeResult struct {
	Revoked int      `json:"revoked"`
	IDs     []string `json:"lease_ids"`
}

// BulkRevoke revokes active leases matching criteria.
func (s *LeaseService) BulkRevoke(ctx context.Context, req BulkRevokeRequest) (*BulkRevokeResult, error) {
	leases, err := s.List(ctx, LeaseListFilter{
		Engine:     req.Engine,
		Role:       req.Role,
		Prefix:     req.PathPrefix,
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}
	result := &BulkRevokeResult{}
	for _, view := range leases {
		if err := s.revokeOne(ctx, view.ID, view.Engine); err != nil {
			return nil, err
		}
		result.Revoked++
		result.IDs = append(result.IDs, view.ID)
	}
	return result, nil
}

func (s *LeaseService) revokeOne(ctx context.Context, id, engine string) error {
	var err error
	switch engine {
	case "database":
		if s.database == nil {
			return common.New(common.ErrCodeInternal, "database engine not configured")
		}
		_, err = s.database.RevokeLease(ctx, id)
	case "ssh":
		if s.ssh == nil {
			return common.New(common.ErrCodeInternal, "ssh engine not configured")
		}
		err = s.ssh.RevokeLease(ctx, id)
	default:
		err = common.New(common.ErrCodeValidation, "unsupported lease engine")
	}
	audithelper.Record(s.audit, ctx, "lease.revoke", "sys/leases/"+id, err, map[string]any{"lease_id": id, "engine": engine})
	return err
}

func toLeaseView(lease *domainsecrets.Lease) *LeaseView {
	if lease == nil {
		return nil
	}
	return &LeaseView{
		ID:         lease.ID,
		Engine:     lease.Engine,
		Role:       lease.RoleName,
		Path:       lease.Path,
		TTLSeconds: lease.TTLSeconds,
		ExpiresAt:  lease.ExpiresAt,
		Renewable:  lease.Renewable,
		Revoked:    lease.RevokedAt != nil,
		RevokedAt:  lease.RevokedAt,
	}
}
