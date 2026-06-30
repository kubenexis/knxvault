package service

import (
	"context"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/notify"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// RotationService manages KV rotation policies and scheduled rotation.
type RotationService struct {
	policies repository.RotationPolicyRepository
	secrets  *SecretsService
	audit    *auditsvc.Service
	webhook  *notify.Webhook
}

// NewRotationService constructs a rotation service.
func NewRotationService(
	policies repository.RotationPolicyRepository,
	secrets *SecretsService,
	audit *auditsvc.Service,
	webhookURL string,
) *RotationService {
	return &RotationService{
		policies: policies,
		secrets:  secrets,
		audit:    audit,
		webhook:  notify.NewWebhook(webhookURL),
	}
}

// PutPolicy stores or updates a rotation policy.
func (s *RotationService) PutPolicy(ctx context.Context, policy *domainsecrets.RotationPolicy) error {
	if s == nil || s.policies == nil {
		return nil
	}
	policy.Enabled = true
	err := s.policies.Save(ctx, policy)
	audithelper.Record(s.audit, ctx, "rotation.policy.set", "secrets/kv/"+policy.Path, err, nil)
	return err
}

// DeletePolicy disables rotation for a path.
func (s *RotationService) DeletePolicy(ctx context.Context, path string) error {
	if s == nil || s.policies == nil {
		return nil
	}
	err := s.policies.Delete(ctx, path)
	audithelper.Record(s.audit, ctx, "rotation.policy.delete", "secrets/kv/"+path, err, nil)
	return err
}

// GetPolicy returns a rotation policy.
func (s *RotationService) GetPolicy(ctx context.Context, path string) (*domainsecrets.RotationPolicy, error) {
	if s == nil || s.policies == nil {
		return nil, nil
	}
	return s.policies.Get(ctx, path)
}

// RunDue rotates all policies that are due at now.
func (s *RotationService) RunDue(ctx context.Context, now time.Time) (int, error) {
	if s == nil || s.policies == nil || s.secrets == nil {
		return 0, nil
	}
	policies, err := s.policies.List(ctx)
	if err != nil {
		return 0, err
	}
	rotated := 0
	for _, policy := range policies {
		if !policy.Due(now) {
			continue
		}
		if err := s.RotatePath(ctx, policy); err != nil {
			continue
		}
		rotated++
	}
	return rotated, nil
}

// RotatePath rotates a single path per policy.
func (s *RotationService) RotatePath(ctx context.Context, policy *domainsecrets.RotationPolicy) error {
	if policy == nil {
		return nil
	}
	data, err := secretsengine.GenerateRotationValue(policy.Generator)
	if err != nil {
		return err
	}
	prev, _ := s.secrets.Get(ctx, policy.Path)
	oldVersion := 0
	if prev != nil {
		oldVersion = prev.Version
	}
	newVersion := 0
	result, err := s.secrets.Put(ctx, policy.Path, data, secretsengine.PutOptions{})
	if result != nil {
		newVersion = result.Version
	}
	audithelper.Record(s.audit, ctx, "secret.rotate", "secrets/kv/"+policy.Path, err, map[string]any{
		"old_version": oldVersion,
		"new_version": newVersion,
	})
	if err != nil {
		return err
	}
	policy.LastRotatedAt = time.Now().UTC()
	_ = s.policies.Save(ctx, policy)
	if s.webhook != nil {
		_ = s.webhook.Send(ctx, notify.Event{
			Event:   "secret.rotate",
			Path:    policy.Path,
			Details: map[string]any{"version": result.Version},
		})
	}
	return nil
}
