package service

import (
	"context"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	sshengine "github.com/kubenexis/knxvault/internal/engine/secrets/ssh"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// SSHService coordinates dynamic OpenSSH credential operations.
type SSHService struct {
	engine *sshengine.Engine
	audit  *auditsvc.Service
}

// NewSSHService constructs an SSH credentials service.
func NewSSHService(engine *sshengine.Engine, audit *auditsvc.Service) *SSHService {
	return &SSHService{engine: engine, audit: audit}
}

// SaveRole stores SSH role configuration.
func (s *SSHService) SaveRole(ctx context.Context, cfg sshengine.RoleConfig) error {
	err := s.engine.SaveRole(ctx, cfg)
	audithelper.Record(s.audit, ctx, "ssh.role.write", "secrets/ssh/roles/"+cfg.Name, err, nil)
	return err
}

// GetRole returns SSH role configuration.
func (s *SSHService) GetRole(ctx context.Context, name string) (*domainsecrets.SSHRole, error) {
	return s.engine.GetRole(ctx, name)
}

// GenerateCredentials issues short-lived SSH credentials.
func (s *SSHService) GenerateCredentials(ctx context.Context, req sshengine.CredsRequest) (*sshengine.CredsResult, error) {
	result, err := s.engine.GenerateCredentials(ctx, req)
	details := map[string]any{"role": req.Role}
	if result != nil {
		details["lease_id"] = result.LeaseID
		details["username"] = result.Username
	}
	audithelper.Record(s.audit, ctx, "ssh.creds.generate", "secrets/ssh/creds/"+req.Role, err, details)
	return result, err
}

// Renew extends a lease.
func (s *SSHService) Renew(ctx context.Context, leaseID string, ttlSeconds int) (*sshengine.CredsResult, error) {
	result, err := s.engine.Renew(ctx, leaseID, ttlSeconds)
	audithelper.Record(s.audit, ctx, "ssh.lease.renew", "secrets/ssh/leases/"+leaseID, err, map[string]any{"lease_id": leaseID})
	return result, err
}

// Revoke revokes a lease.
func (s *SSHService) Revoke(ctx context.Context, leaseID string) error {
	err := s.engine.RevokeLease(ctx, leaseID)
	audithelper.Record(s.audit, ctx, "ssh.lease.revoke", "secrets/ssh/leases/"+leaseID, err, map[string]any{"lease_id": leaseID})
	return err
}

// CleanupExpired revokes expired ssh leases (background job).
func (s *SSHService) CleanupExpired(ctx context.Context, limit int) (int, error) {
	count, err := s.engine.CleanupExpired(ctx, limit)
	if err == nil && count > 0 {
		audithelper.Record(s.audit, ctx, "ssh.lease.cleanup", "secrets/ssh/leases", nil, map[string]any{"revoked": count})
	}
	return count, err
}
