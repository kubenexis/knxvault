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

func TestServiceExportAuditEntryFormat(t *testing.T) {
	repo := memory.NewAuditRepository()
	svc := audit.NewService(repo)
	svc.SetSigningKey([]byte("signing-key"))

	ctx := context.Background()
	details := map[string]any{"path": "app/db", "version": 1}
	if err := svc.Record(ctx, "alice", "secret.read", "secrets/kv/app/db", "success", details); err != nil {
		t.Fatalf("Record() = %v", err)
	}

	exported, err := svc.Export(ctx, repository.AuditListOptions{})
	if err != nil {
		t.Fatalf("Export() = %v", err)
	}
	if len(exported.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(exported.Entries))
	}
	entry := exported.Entries[0]
	if entry.Actor != "alice" || entry.Action != "secret.read" || entry.Resource != "secrets/kv/app/db" {
		t.Fatalf("unexpected entry fields: %+v", entry)
	}
	if entry.Status != "success" || entry.Hash == "" {
		t.Fatalf("status/hash missing: %+v", entry)
	}
	if entry.Signature == "" {
		t.Fatal("expected per-entry signature when signing key configured")
	}
	if entry.Timestamp.IsZero() {
		t.Fatal("expected timestamp")
	}
}

func TestServiceVerifyDetectsSignatureTampering(t *testing.T) {
	repo := memory.NewAuditRepository()
	svc := audit.NewService(repo)
	svc.SetSigningKey([]byte("signing-key"))
	ctx := context.Background()
	if err := svc.Record(ctx, "alice", "secret.write", "app/x", "success", nil); err != nil {
		t.Fatalf("Record() = %v", err)
	}

	entries, err := repo.List(ctx, repository.AuditListOptions{OrderAsc: true})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	entries[0].Signature = "deadbeef"
	if err := repo.Append(ctx, entries[0]); err != nil {
		t.Fatalf("Append() = %v", err)
	}

	verified, err := svc.Verify(ctx, "", time.Time{})
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if verified.Valid {
		t.Fatal("expected invalid chain after signature tampering")
	}
	if verified.Message == "" {
		t.Fatal("expected verification message")
	}
}

func TestServiceVerifyChainCompleteness(t *testing.T) {
	repo := memory.NewAuditRepository()
	svc := audit.NewService(repo)
	ctx := context.Background()
	if err := svc.Record(ctx, "a", "read", "r1", "success", nil); err != nil {
		t.Fatalf("Record() = %v", err)
	}
	if err := svc.Record(ctx, "b", "write", "r2", "success", nil); err != nil {
		t.Fatalf("Record() = %v", err)
	}

	verified, err := svc.Verify(ctx, "", time.Time{})
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if !verified.Valid {
		t.Fatalf("expected complete chain, got %q", verified.Message)
	}
	head, err := repo.LatestHash(ctx)
	if err != nil {
		t.Fatalf("LatestHash() = %v", err)
	}
	if verified.HeadHash != head {
		t.Fatalf("head hash = %q, want %q", verified.HeadHash, head)
	}
}
