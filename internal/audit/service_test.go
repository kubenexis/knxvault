package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestServiceRecordExportVerify(t *testing.T) {
	repo := memory.NewAuditRepository()
	svc := audit.NewService(repo)
	svc.SetSigningKey([]byte("test-signing-key"))

	ctx := context.Background()
	if err := svc.Record(ctx, "tester", "secret.read", "app/db", "success", map[string]any{"v": 1}); err != nil {
		t.Fatalf("Record() = %v", err)
	}
	if err := svc.Record(ctx, "tester", "secret.write", "app/db", "success", nil); err != nil {
		t.Fatalf("Record() = %v", err)
	}

	exported, err := svc.Export(ctx, repository.AuditListOptions{})
	if err != nil {
		t.Fatalf("Export() = %v", err)
	}
	if len(exported.Entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(exported.Entries))
	}
	if exported.HeadHash == "" || exported.Signature == "" {
		t.Fatal("expected head hash and signature")
	}

	verified, err := svc.Verify(ctx, exported.Signature, exported.SignedAt)
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if !verified.Valid {
		t.Fatalf("expected valid chain, got %q", verified.Message)
	}
}

func TestServiceVerifyDetectsTampering(t *testing.T) {
	repo := memory.NewAuditRepository()
	svc := audit.NewService(repo)
	ctx := context.Background()
	if err := svc.Record(ctx, "tester", "secret.read", "app/db", "success", nil); err != nil {
		t.Fatalf("Record() = %v", err)
	}

	entries, err := repo.List(ctx, repository.AuditListOptions{OrderAsc: true})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	entries[0].Hash = "deadbeef"
	if err := repo.Append(ctx, entries[0]); err != nil {
		t.Fatalf("Append() = %v", err)
	}

	verified, err := svc.Verify(ctx, "", time.Time{})
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if verified.Valid {
		t.Fatal("expected invalid chain after tampering")
	}
}
