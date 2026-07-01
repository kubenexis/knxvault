package service

import (
	"context"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/inject"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
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

// Render materializes secrets for injection.
func (s *InjectService) Render(ctx context.Context, req inject.RenderRequest) (*inject.RenderResult, error) {
	result, err := s.renderer.Render(ctx, req)
	audithelper.Record(s.audit, ctx, "inject.render", "inject/render", err, map[string]any{"count": len(req.Secrets)})
	return result, err
}

// CSIMountAuditRequest describes a successful CSI provider mount.
type CSIMountAuditRequest struct {
	Role           string
	Namespace      string
	ServiceAccount string
	PodName        string
	Paths          []string
}

// RecordCSIMount appends a csi.mount audit event for pod identity mounts.
func (s *InjectService) RecordCSIMount(ctx context.Context, req CSIMountAuditRequest) error {
	audithelper.Record(s.audit, ctx, "csi.mount", "inject/csi/mount", nil, map[string]any{
		"role":            req.Role,
		"namespace":       req.Namespace,
		"service_account": req.ServiceAccount,
		"pod_name":        req.PodName,
		"paths":           req.Paths,
	})
	return nil
}
