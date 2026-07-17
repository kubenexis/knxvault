// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/repository"
)

// AuditPackService builds compliance audit bundles (W35-02).
type AuditPackService struct {
	audit *auditsvc.Service
}

// NewAuditPackService constructs an audit pack service.
func NewAuditPackService(audit *auditsvc.Service) *AuditPackService {
	return &AuditPackService{audit: audit}
}

// Pack builds a zip archive with audit export and manifest.
func (s *AuditPackService) Pack(ctx context.Context, since *time.Time) ([]byte, error) {
	if s == nil || s.audit == nil {
		return nil, nil
	}
	opts := repository.AuditListOptions{Limit: 10000}
	if since != nil {
		opts.Since = since
	}
	export, err := s.audit.Export(ctx, opts)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	manifest := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"entry_count":  len(export.Entries),
		"head_hash":    export.HeadHash,
	}
	manifestRaw, _ := json.MarshalIndent(manifest, "", "  ")
	mf, _ := zw.Create("manifest.json")
	_, _ = mf.Write(manifestRaw)
	entriesRaw, _ := json.MarshalIndent(export, "", "  ")
	ef, _ := zw.Create("audit-export.json")
	_, _ = ef.Write(entriesRaw)
	_ = zw.Close()
	return buf.Bytes(), nil
}
