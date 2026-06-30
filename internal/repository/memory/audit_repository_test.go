package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/audit"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestAuditRepositoryAppendList(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewAuditRepository()

	entry := &audit.Entry{
		Timestamp: time.Now().UTC(),
		Actor:     "tester",
		Action:    "secret.read",
		Resource:  "app/db",
		Status:    "success",
		Details:   map[string]any{"version": 1},
	}
	if err := repo.Append(ctx, entry); err != nil {
		t.Fatalf("Append() = %v", err)
	}
	if entry.ID == 0 {
		t.Fatal("expected assigned audit id")
	}

	list, err := repo.List(ctx, repository.AuditListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len(List()) = %d, want 1", len(list))
	}
	if list[0].Action != "secret.read" {
		t.Fatalf("Action = %q, want secret.read", list[0].Action)
	}
}
