package service

import (
	"context"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
)

// SecretsService coordinates KV secret operations with audit logging.
type SecretsService struct {
	engine *secretsengine.KVV2Engine
	audit  *auditsvc.Service
}

// NewSecretsService constructs a secrets service.
func NewSecretsService(engine *secretsengine.KVV2Engine, audit *auditsvc.Service) *SecretsService {
	return &SecretsService{engine: engine, audit: audit}
}

func (s *SecretsService) actor(ctx context.Context) string {
	if principal, ok := auth.PrincipalFromContext(ctx); ok {
		return principal.Subject
	}
	return "anonymous"
}

// Put stores a secret version.
func (s *SecretsService) Put(ctx context.Context, path string, data map[string]any, opts secretsengine.PutOptions) (*secretsengine.PutResult, error) {
	result, err := s.engine.Put(ctx, path, data, opts)
	s.record(ctx, "secret.write", "secrets/kv/"+path, err, nil)
	return result, err
}

// Get reads the latest secret version.
func (s *SecretsService) Get(ctx context.Context, path string) (*secretsengine.GetResult, error) {
	result, err := s.engine.Get(ctx, path)
	s.record(ctx, "secret.read", "secrets/kv/"+path, err, nil)
	return result, err
}

// Delete soft-deletes a secret path.
func (s *SecretsService) Delete(ctx context.Context, path string) error {
	err := s.engine.Delete(ctx, path)
	s.record(ctx, "secret.delete", "secrets/kv/"+path, err, nil)
	return err
}

func (s *SecretsService) record(ctx context.Context, action, resource string, err error, details map[string]any) {
	if s.audit == nil {
		return
	}
	status := "success"
	if err != nil {
		status = "failure"
	}
	_ = s.audit.Record(ctx, s.actor(ctx), action, resource, status, details)
}
