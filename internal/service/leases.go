// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	sshengine "github.com/kubenexis/knxvault/internal/engine/secrets/ssh"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
	"github.com/kubenexis/knxvault/internal/tenant"
)

// LeaseRevoker is called when a lease is revoked (engine-specific cleanup).
type LeaseRevoker interface {
	RevokeLease(ctx context.Context, leaseID string) error
}

// LeaseRenewer extends a lease TTL in an engine.
type LeaseRenewer interface {
	Renew(ctx context.Context, leaseID string, ttlSeconds int) error
}

// LeaseService provides unified lease operations (M-LEASE-1 / W67).
type LeaseService struct {
	leases   repository.LeaseRepository
	database *databaseengine.Engine
	ssh      *sshengine.Engine
	audit    *auditsvc.Service

	mu         sync.RWMutex
	hooks      map[string]LeaseRevoker // engine name -> revoker
	renewers   map[string]LeaseRenewer
	tenantMode bool
}

// NewLeaseService constructs a lease service.
func NewLeaseService(
	leases repository.LeaseRepository,
	database *databaseengine.Engine,
	ssh *sshengine.Engine,
	audit *auditsvc.Service,
) *LeaseService {
	s := &LeaseService{
		leases:   leases,
		database: database,
		ssh:      ssh,
		audit:    audit,
		hooks:    make(map[string]LeaseRevoker),
		renewers: make(map[string]LeaseRenewer),
	}
	if database != nil {
		s.hooks["database"] = dbRevoker{database}
		s.renewers["database"] = dbRenewer{database}
	}
	if ssh != nil {
		s.hooks["ssh"] = sshRevoker{ssh}
		s.renewers["ssh"] = sshRenewer{ssh}
	}
	return s
}

// RegisterRevoker registers an OnRevoke hook for an engine name.
func (s *LeaseService) RegisterRevoker(engine string, r LeaseRevoker) {
	if s == nil || engine == "" || r == nil {
		return
	}
	s.mu.Lock()
	s.hooks[engine] = r
	s.mu.Unlock()
}

// RegisterRenewer registers a renew hook for an engine.
func (s *LeaseService) RegisterRenewer(engine string, r LeaseRenewer) {
	if s == nil || engine == "" || r == nil {
		return
	}
	s.mu.Lock()
	s.renewers[engine] = r
	s.mu.Unlock()
}

// LeaseView is engine-agnostic lease metadata.
type LeaseView struct {
	ID         string            `json:"lease_id"`
	Engine     string            `json:"engine"`
	Role       string            `json:"role"`
	Path       string            `json:"path"`
	TTLSeconds int               `json:"ttl_seconds"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Renewable  bool              `json:"renewable"`
	Revoked    bool              `json:"revoked"`
	RevokedAt  *time.Time        `json:"revoked_at,omitempty"`
	TokenID    string            `json:"token_id,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// LeaseListFilter filters lease list queries.
type LeaseListFilter struct {
	Engine     string
	Role       string
	Prefix     string
	TokenID    string
	ActiveOnly bool
	Limit      int
	Offset     int
}

// Register creates a lease record (engines may also Save directly; prefer this for token binding).
func (s *LeaseService) Register(ctx context.Context, lease *domainsecrets.Lease) error {
	if s == nil || s.leases == nil {
		return common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	if lease == nil {
		return common.New(common.ErrCodeValidation, "lease required")
	}
	if s.tenantMode {
		if ns := tenantNamespaceFromCtx(ctx); ns != "" {
			lease.ID = tenant.ScopeLeaseID(ns, lease.ID, true)
		}
	}
	if err := lease.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "lease", err)
	}
	return s.leases.Save(ctx, lease)
}

// Get returns lease metadata by ID.
func (s *LeaseService) Get(ctx context.Context, id string) (*LeaseView, error) {
	if s == nil || s.leases == nil {
		return nil, common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	if err := s.checkTenantLease(ctx, id); err != nil {
		return nil, err
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
	tenantNS := ""
	if s.tenantMode {
		tenantNS = tenantNamespaceFromCtx(ctx)
	}
	var out []LeaseView
	for _, lease := range all {
		if tenantNS != "" && !tenant.ValidateLeaseIDAccess(tenantNS, lease.ID, true) {
			continue
		}
		if filter.Engine != "" && lease.Engine != filter.Engine {
			continue
		}
		if filter.Role != "" && lease.RoleName != filter.Role {
			continue
		}
		if filter.Prefix != "" && !strings.HasPrefix(lease.Path, filter.Prefix) {
			continue
		}
		if filter.TokenID != "" && lease.TokenID != filter.TokenID {
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

// Renew extends a lease via the engine renewer or repository TTL update.
func (s *LeaseService) Renew(ctx context.Context, id string, ttlSeconds int) (*LeaseView, error) {
	if s == nil || s.leases == nil {
		return nil, common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	if err := s.checkTenantLease(ctx, id); err != nil {
		return nil, err
	}
	lease, err := s.leases.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !lease.Active(time.Now().UTC()) {
		return nil, common.New(common.ErrCodeValidation, "lease not active")
	}
	if !lease.Renewable {
		return nil, common.New(common.ErrCodeValidation, "lease is not renewable")
	}
	if ttlSeconds <= 0 {
		ttlSeconds = lease.TTLSeconds
	}
	s.mu.RLock()
	renewer := s.renewers[lease.Engine]
	s.mu.RUnlock()
	if renewer != nil {
		if err := renewer.Renew(ctx, id, ttlSeconds); err != nil {
			audithelper.Record(s.audit, ctx, "lease.renew", "sys/leases/"+id, err, nil)
			return nil, err
		}
	} else {
		// Cap generic renewals (engines enforce their own MaxTTL).
		const maxGenericRenewTTL = 24 * 3600
		if ttlSeconds > maxGenericRenewTTL {
			ttlSeconds = maxGenericRenewTTL
		}
		lease.TTLSeconds = ttlSeconds
		lease.ExpiresAt = time.Now().UTC().Add(time.Duration(ttlSeconds) * time.Second)
		if err := s.leases.Save(ctx, lease); err != nil {
			return nil, err
		}
	}
	updated, err := s.leases.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	audithelper.Record(s.audit, ctx, "lease.renew", "sys/leases/"+id, nil, map[string]any{"ttl": ttlSeconds})
	return toLeaseView(updated), nil
}

// Revoke revokes a single lease via engine hook + repository.
func (s *LeaseService) Revoke(ctx context.Context, id string) error {
	if s == nil || s.leases == nil {
		return common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	if err := s.checkTenantLease(ctx, id); err != nil {
		return err
	}
	lease, err := s.leases.Get(ctx, id)
	if err != nil {
		return err
	}
	return s.revokeOne(ctx, lease.ID, lease.Engine)
}

// RevokePrefix revokes active leases under a path prefix.
func (s *LeaseService) RevokePrefix(ctx context.Context, prefix string) (*BulkRevokeResult, error) {
	if strings.TrimSpace(prefix) == "" {
		return nil, common.New(common.ErrCodeValidation, "prefix is required")
	}
	return s.BulkRevoke(ctx, BulkRevokeRequest{PathPrefix: prefix})
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
// W74-06: require at least one selector (engine, role, or path_prefix) to avoid mass revoke DoS.
func (s *LeaseService) BulkRevoke(ctx context.Context, req BulkRevokeRequest) (*BulkRevokeResult, error) {
	if strings.TrimSpace(req.Engine) == "" && strings.TrimSpace(req.Role) == "" && strings.TrimSpace(req.PathPrefix) == "" {
		return nil, common.New(common.ErrCodeValidation, "bulk revoke requires engine, role, or path_prefix")
	}
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
			if result.Revoked > 0 {
				return result, fmt.Errorf("partial bulk revoke after %d leases: %w", result.Revoked, err)
			}
			return nil, err
		}
		result.Revoked++
		result.IDs = append(result.IDs, view.ID)
	}
	return result, nil
}

// Tidy revokes expired leases (force cleanup).
func (s *LeaseService) Tidy(ctx context.Context, limit int) (int, error) {
	if s == nil || s.leases == nil {
		return 0, common.New(common.ErrCodeInternal, "lease repository not configured")
	}
	if limit <= 0 {
		limit = 100
	}
	expired, err := s.leases.ListExpired(ctx, time.Now().UTC(), limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, lease := range expired {
		if lease.RevokedAt != nil {
			continue
		}
		if err := s.revokeOne(ctx, lease.ID, lease.Engine); err != nil {
			// best-effort continue
			continue
		}
		n++
	}
	audithelper.Record(s.audit, ctx, "lease.tidy", "sys/leases", nil, map[string]any{"revoked": n})
	return n, nil
}

// RevokeByTokenID cascades lease revocation when a client token is revoked.
func (s *LeaseService) RevokeByTokenID(ctx context.Context, tokenID string) (int, error) {
	if tokenID == "" {
		return 0, nil
	}
	leases, err := s.List(ctx, LeaseListFilter{TokenID: tokenID, ActiveOnly: true})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range leases {
		if err := s.revokeOne(ctx, v.ID, v.Engine); err != nil {
			continue
		}
		n++
	}
	if n > 0 {
		audithelper.Record(s.audit, ctx, "lease.cascade_revoke", "sys/leases", nil, map[string]any{"token_id": tokenID, "count": n})
	}
	return n, nil
}

// tenantMode / checkTenantLease optional via SetTenantMode.
func (s *LeaseService) SetTenantMode(enabled bool) {
	if s != nil {
		s.tenantMode = enabled
	}
}

func (s *LeaseService) checkTenantLease(ctx context.Context, id string) error {
	if s == nil || !s.tenantMode {
		return nil
	}
	ns := tenantNamespaceFromCtx(ctx)
	if ns == "" {
		return nil // non-SA callers without ns: no extra check
	}
	if !tenant.ValidateLeaseIDAccess(ns, id, true) {
		return common.New(common.ErrCodeForbidden, "cross-tenant lease access denied")
	}
	return nil
}

func tenantNamespaceFromCtx(ctx context.Context) string {
	if rc, ok := auth.RequestContextFromContext(ctx); ok {
		return strings.TrimSpace(rc.Namespace)
	}
	return ""
}

func (s *LeaseService) revokeOne(ctx context.Context, id, engine string) error {
	s.mu.RLock()
	hook := s.hooks[engine]
	s.mu.RUnlock()
	var err error
	if hook != nil {
		err = hook.RevokeLease(ctx, id)
	} else {
		// Generic path: mark revoked only
		err = s.leases.Revoke(ctx, id, time.Now().UTC())
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
		TokenID:    lease.TokenID,
		Metadata:   lease.Metadata,
	}
}

type dbRevoker struct{ e *databaseengine.Engine }

func (d dbRevoker) RevokeLease(ctx context.Context, id string) error {
	_, err := d.e.RevokeLease(ctx, id)
	return err
}

type sshRevoker struct{ e *sshengine.Engine }

func (d sshRevoker) RevokeLease(ctx context.Context, id string) error {
	return d.e.RevokeLease(ctx, id)
}

type dbRenewer struct{ e *databaseengine.Engine }

func (d dbRenewer) Renew(ctx context.Context, id string, ttl int) error {
	_, err := d.e.Renew(ctx, id, ttl)
	return err
}

type sshRenewer struct{ e *sshengine.Engine }

func (d sshRenewer) Renew(ctx context.Context, id string, ttl int) error {
	_, err := d.e.Renew(ctx, id, ttl)
	return err
}
