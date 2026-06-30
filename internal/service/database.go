package service

import (
	"context"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
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

func (s *DatabaseService) actor(ctx context.Context) string {
	if principal, ok := auth.PrincipalFromContext(ctx); ok {
		return principal.Subject
	}
	return "anonymous"
}

// SaveRole stores database role configuration.
func (s *DatabaseService) SaveRole(ctx context.Context, cfg databaseengine.RoleConfig) error {
	err := s.engine.SaveRole(ctx, cfg)
	s.record(ctx, "database.role.write", "secrets/database/roles/"+cfg.Name, err, nil)
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
	s.record(ctx, "database.creds.generate", "secrets/database/creds/"+req.Role, err, details)
	return result, err
}

// Renew extends a lease.
func (s *DatabaseService) Renew(ctx context.Context, leaseID string, ttlSeconds int) (*databaseengine.CredsResult, error) {
	result, err := s.engine.Renew(ctx, leaseID, ttlSeconds)
	s.record(ctx, "database.lease.renew", "secrets/database/leases/"+leaseID, err, map[string]any{"lease_id": leaseID})
	return result, err
}

// Revoke revokes a lease.
func (s *DatabaseService) Revoke(ctx context.Context, leaseID string) error {
	err := s.engine.RevokeLease(ctx, leaseID)
	s.record(ctx, "database.lease.revoke", "secrets/database/leases/"+leaseID, err, map[string]any{"lease_id": leaseID})
	return err
}

// CleanupExpired revokes expired leases (background job).
func (s *DatabaseService) CleanupExpired(ctx context.Context, limit int) (int, error) {
	count, err := s.engine.CleanupExpired(ctx, limit)
	if err == nil && count > 0 {
		s.record(ctx, "database.lease.cleanup", "secrets/database/leases", nil, map[string]any{"revoked": count})
	}
	return count, err
}

func (s *DatabaseService) record(ctx context.Context, action, resource string, err error, details map[string]any) {
	if s.audit == nil {
		return
	}
	status := "success"
	if err != nil {
		status = "failure"
	}
	_ = s.audit.Record(ctx, s.actor(ctx), action, resource, status, details)
}
