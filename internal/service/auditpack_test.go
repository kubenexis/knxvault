package service_test

import (
	"archive/zip"
	"bytes"
	"context"
	"testing"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestAuditPackServicePack(t *testing.T) {
	auditRepo := memory.NewAuditRepository()
	audit := auditsvc.NewService(auditRepo)
	svc := service.NewAuditPackService(audit)

	data, err := svc.Pack(context.Background(), nil)
	if err != nil {
		t.Fatalf("Pack() = %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("zip reader = %v", err)
	}
	if len(zr.File) < 2 {
		t.Fatalf("expected manifest and export files, got %d", len(zr.File))
	}
}
