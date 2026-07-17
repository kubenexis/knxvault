// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package audithelper_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

func TestActorAnonymous(t *testing.T) {
	if got := audithelper.Actor(context.Background()); got != "anonymous" {
		t.Fatalf("Actor() = %q, want anonymous", got)
	}
}

func TestActorFromPrincipal(t *testing.T) {
	ctx := auth.WithPrincipal(context.Background(), auth.Principal{Subject: "ci-bot"})
	if got := audithelper.Actor(ctx); got != "ci-bot" {
		t.Fatalf("Actor() = %q, want ci-bot", got)
	}
}

func TestRecordWritesAuditEntry(t *testing.T) {
	repo := memory.NewAuditRepository()
	svc := audit.NewService(repo)
	ctx := auth.WithPrincipal(context.Background(), auth.Principal{Subject: "admin"})

	audithelper.Record(svc, ctx, "test.action", "test/resource", nil, map[string]any{"ok": true})

	entries, err := repo.List(context.Background(), repository.AuditListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Actor != "admin" || entries[0].Status != "success" {
		t.Fatalf("unexpected entry: %+v", entries[0])
	}
}
