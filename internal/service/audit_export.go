// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// AuditExportService exposes audit export and verification APIs.
type AuditExportService struct {
	audit *auditsvc.Service
}

// NewAuditExportService constructs an audit export service.
func NewAuditExportService(audit *auditsvc.Service) *AuditExportService {
	return &AuditExportService{audit: audit}
}

// Export returns audit entries with chain integrity metadata.
func (s *AuditExportService) Export(ctx context.Context, opts repository.AuditListOptions) (*auditsvc.ExportResult, error) {
	result, err := s.audit.Export(ctx, opts)
	count := 0
	if result != nil {
		count = len(result.Entries)
	}
	audithelper.Record(s.audit, ctx, "audit.export", "audit/export", err, map[string]any{"count": count})
	return result, err
}

// Verify checks audit chain integrity and signature.
func (s *AuditExportService) Verify(ctx context.Context, signature string, signedAt time.Time) (*auditsvc.VerifyResult, error) {
	result, err := s.audit.Verify(ctx, signature, signedAt)
	valid := result != nil && result.Valid
	audithelper.Record(s.audit, ctx, "audit.verify", "audit/verify", err, map[string]any{"valid": valid})
	return result, err
}
