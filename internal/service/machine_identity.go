package service

import (
	"context"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// MachineIdentityService manages non-human identities.
type MachineIdentityService struct {
	repo  repository.MachineIdentityRepository
	audit *auditsvc.Service
}

// NewMachineIdentityService constructs the service.
func NewMachineIdentityService(repo repository.MachineIdentityRepository, audit *auditsvc.Service) *MachineIdentityService {
	return &MachineIdentityService{repo: repo, audit: audit}
}

// UpsertFromLogin creates or updates an identity after successful login.
func (s *MachineIdentityService) UpsertFromLogin(ctx context.Context, identity *domainauth.MachineIdentity) error {
	if s == nil || s.repo == nil || identity == nil {
		return nil
	}
	identity.LastSeen = time.Now().UTC()
	err := s.repo.Save(ctx, identity)
	audithelper.Record(s.audit, ctx, "nhi.login", "sys/machine-identities/"+identity.ID, err, map[string]any{
		"actor_type": "nhi",
		"type":       identity.Type,
	})
	return err
}

// IsRevoked reports whether the identity is revoked.
func (s *MachineIdentityService) IsRevoked(ctx context.Context, id string) (bool, error) {
	if s == nil || s.repo == nil {
		return false, nil
	}
	rec, err := s.repo.Get(ctx, id)
	if err != nil {
		return false, err
	}
	return rec.Revoked, nil
}

// List returns all machine identities.
func (s *MachineIdentityService) List(ctx context.Context) ([]*domainauth.MachineIdentity, error) {
	if s == nil || s.repo == nil {
		return nil, nil
	}
	return s.repo.List(ctx)
}

// Revoke blocks future logins for the identity.
func (s *MachineIdentityService) Revoke(ctx context.Context, id string) error {
	if s == nil || s.repo == nil {
		return nil
	}
	err := s.repo.Revoke(ctx, id)
	audithelper.Record(s.audit, ctx, "nhi.revoke", "sys/machine-identities/"+id, err, nil)
	return err
}
