package service

import (
	"context"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/inject"
)

// InjectService renders secrets for sidecar and init-container injection.
type InjectService struct {
	renderer *inject.Renderer
	audit    *auditsvc.Service
}

// NewInjectService constructs an injection service.
func NewInjectService(renderer *inject.Renderer, audit *auditsvc.Service) *InjectService {
	return &InjectService{renderer: renderer, audit: audit}
}

func (s *InjectService) actor(ctx context.Context) string {
	if principal, ok := auth.PrincipalFromContext(ctx); ok {
		return principal.Subject
	}
	return "anonymous"
}

// Render materializes secrets for injection.
func (s *InjectService) Render(ctx context.Context, req inject.RenderRequest) (*inject.RenderResult, error) {
	result, err := s.renderer.Render(ctx, req)
	s.record(ctx, "inject.render", "inject/render", err, map[string]any{"count": len(req.Secrets)})
	return result, err
}

func (s *InjectService) record(ctx context.Context, action, resource string, err error, details map[string]any) {
	if s.audit == nil {
		return
	}
	status := "success"
	if err != nil {
		status = "failure"
	}
	_ = s.audit.Record(ctx, s.actor(ctx), action, resource, status, details)
}
