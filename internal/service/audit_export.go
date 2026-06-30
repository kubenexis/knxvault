package service

import (
	"context"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/repository"
)

// AuditExportService exposes audit export and verification APIs.
type AuditExportService struct {
	audit *auditsvc.Service
}

// NewAuditExportService constructs an audit export service.
func NewAuditExportService(audit *auditsvc.Service) *AuditExportService {
	return &AuditExportService{audit: audit}
}

func (s *AuditExportService) actor(ctx context.Context) string {
	if principal, ok := auth.PrincipalFromContext(ctx); ok {
		return principal.Subject
	}
	return "anonymous"
}

// Export returns audit entries with chain integrity metadata.
func (s *AuditExportService) Export(ctx context.Context, opts repository.AuditListOptions) (*auditsvc.ExportResult, error) {
	result, err := s.audit.Export(ctx, opts)
	count := 0
	if result != nil {
		count = len(result.Entries)
	}
	s.record(ctx, "audit.export", "audit/export", err, map[string]any{"count": count})
	return result, err
}

// Verify checks audit chain integrity and signature.
func (s *AuditExportService) Verify(ctx context.Context, signature string, signedAt time.Time) (*auditsvc.VerifyResult, error) {
	result, err := s.audit.Verify(ctx, signature, signedAt)
	valid := result != nil && result.Valid
	s.record(ctx, "audit.verify", "audit/verify", err, map[string]any{"valid": valid})
	return result, err
}

func (s *AuditExportService) record(ctx context.Context, action, resource string, err error, details map[string]any) {
	if s.audit == nil {
		return
	}
	status := "success"
	if err != nil {
		status = "failure"
	}
	_ = s.audit.Record(ctx, s.actor(ctx), action, resource, status, details)
}
