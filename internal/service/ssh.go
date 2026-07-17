// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	sshengine "github.com/kubenexis/knxvault/internal/engine/secrets/ssh"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// SSHService coordinates dynamic OpenSSH credential operations.
type SSHService struct {
	engine     *sshengine.Engine
	audit      *auditsvc.Service
	tenantMode bool
}

// NewSSHService constructs an SSH credentials service.
func NewSSHService(engine *sshengine.Engine, audit *auditsvc.Service) *SSHService {
	return &SSHService{engine: engine, audit: audit}
}

// SetTenantMode enables tenant-scoped role names (W32-04 / W53).
func (s *SSHService) SetTenantMode(enabled bool) {
	if s != nil {
		s.tenantMode = enabled
	}
}

// SaveRole stores SSH role configuration.
func (s *SSHService) SaveRole(ctx context.Context, cfg sshengine.RoleConfig) error {
	name, err := scopeResourceName(ctx, s.tenantMode, cfg.Name)
	if err != nil {
		return err
	}
	cfg.Name = name
	err = s.engine.SaveRole(ctx, cfg)
	audithelper.Record(s.audit, ctx, "ssh.role.write", "secrets/ssh/roles/"+cfg.Name, err, nil)
	return err
}

// GetRole returns SSH role configuration.
func (s *SSHService) GetRole(ctx context.Context, name string) (*domainsecrets.SSHRole, error) {
	name, err := scopeResourceName(ctx, s.tenantMode, name)
	if err != nil {
		return nil, err
	}
	if err := assertTenantAccess(ctx, s.tenantMode, name); err != nil {
		return nil, err
	}
	return s.engine.GetRole(ctx, name)
}

// GenerateCredentials issues short-lived SSH credentials.
func (s *SSHService) GenerateCredentials(ctx context.Context, req sshengine.CredsRequest) (*sshengine.CredsResult, error) {
	role, err := scopeResourceName(ctx, s.tenantMode, req.Role)
	if err != nil {
		return nil, err
	}
	req.Role = role
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

// RenewExpiring renews active leases expiring within the grace window.
func (s *SSHService) RenewExpiring(ctx context.Context, grace time.Duration, limit int) (int, error) {
	if s == nil || s.engine == nil {
		return 0, nil
	}
	return s.engine.RenewExpiring(ctx, grace, limit)
}

// CleanupExpired revokes expired ssh leases (background job).
func (s *SSHService) CleanupExpired(ctx context.Context, limit int) (int, error) {
	count, err := s.engine.CleanupExpired(ctx, limit)
	if err == nil && count > 0 {
		audithelper.Record(s.audit, ctx, "ssh.lease.cleanup", "secrets/ssh/leases", nil, map[string]any{"revoked": count})
	}
	return count, err
}
