package service

import (
	"context"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// DatabaseService coordinates dynamic database credential operations.
type DatabaseService struct {
	engine *databaseengine.Engine
	audit  *auditsvc.Service
}

// NewDatabaseService constructs a database credentials service.
func NewDatabaseService(engine *databaseengine.Engine, audit *auditsvc.Service) *DatabaseService {
	return &DatabaseService{engine: engine, audit: audit}
}

// SaveRole stores database role configuration.
func (s *DatabaseService) SaveRole(ctx context.Context, cfg databaseengine.RoleConfig) error {
	err := s.engine.SaveRole(ctx, cfg)
	audithelper.Record(s.audit, ctx, "database.role.write", "secrets/database/roles/"+cfg.Name, err, nil)
	return err
}

// GetRole returns database role configuration.
func (s *DatabaseService) GetRole(ctx context.Context, name string) (*domainsecrets.DatabaseRole, error) {
	return s.engine.GetRole(ctx, name)
}

// GenerateCredentials issues short-lived credentials.
func (s *DatabaseService) GenerateCredentials(ctx context.Context, req databaseengine.CredsRequest) (*databaseengine.CredsResult, error) {
	result, err := s.engine.GenerateCredentials(ctx, req)
	details := map[string]any{"role": req.Role}
	if result != nil {
		details["lease_id"] = result.LeaseID
	}
	audithelper.Record(s.audit, ctx, "database.creds.generate", "secrets/database/creds/"+req.Role, err, details)
	return result, err
}

// Renew extends a lease.
func (s *DatabaseService) Renew(ctx context.Context, leaseID string, ttlSeconds int) (*databaseengine.CredsResult, error) {
	result, err := s.engine.Renew(ctx, leaseID, ttlSeconds)
	audithelper.Record(s.audit, ctx, "database.lease.renew", "secrets/database/leases/"+leaseID, err, map[string]any{"lease_id": leaseID})
	return result, err
}

// Revoke revokes a lease and returns client-mode revocation SQL when applicable.
func (s *DatabaseService) Revoke(ctx context.Context, leaseID string) (*databaseengine.RevokeResult, error) {
	result, err := s.engine.RevokeLease(ctx, leaseID)
	audithelper.Record(s.audit, ctx, "database.lease.revoke", "secrets/database/leases/"+leaseID, err, map[string]any{"lease_id": leaseID})
	return result, err
}

// RenewExpiring renews active leases expiring within the grace window.
func (s *DatabaseService) RenewExpiring(ctx context.Context, grace time.Duration, limit int) (int, error) {
	if s == nil || s.engine == nil {
		return 0, nil
	}
	return s.engine.RenewExpiring(ctx, grace, limit)
}

// CleanupExpired revokes expired leases (background job).
func (s *DatabaseService) CleanupExpired(ctx context.Context, limit int) (int, error) {
	count, err := s.engine.CleanupExpired(ctx, limit)
	if err == nil && count > 0 {
		audithelper.Record(s.audit, ctx, "database.lease.cleanup", "secrets/database/leases", nil, map[string]any{"revoked": count})
	}
	return count, err
}
