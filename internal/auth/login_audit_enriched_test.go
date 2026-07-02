package auth_test

import (
	"context"
	"testing"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

type auditSpy struct {
	lastAction  string
	lastStatus  string
	lastDetails map[string]any
}

func (s *auditSpy) Record(_ context.Context, _, action, _, status string, details map[string]any) error {
	s.lastAction = action
	s.lastStatus = status
	s.lastDetails = details
	return nil
}

func TestLoginWithTokenEndpointAuditsFailure(t *testing.T) {
	spy := &auditSpy{}
	store := auth.NewTokenStore(time.Hour)
	svc := auth.NewService(store, auth.NewRBAC(), "")
	svc.SetAuditRecorder(spy)

	ctx := auth.WithLoginAuditContext(context.Background(), "10.0.0.1", "req-42")
	if _, err := svc.LoginWithTokenEndpoint(ctx, "not-a-real-token"); err == nil {
		t.Fatal("expected auth failure")
	}
	if spy.lastAction != "auth.login.failed" {
		t.Fatalf("action = %q", spy.lastAction)
	}
	if spy.lastDetails["request_id"] != "req-42" {
		t.Fatalf("request_id = %v", spy.lastDetails["request_id"])
	}
}

func TestLockoutEmitsAuditEvent(t *testing.T) {
	spy := &auditSpy{}
	store := auth.NewTokenStore(time.Hour)
	svc := auth.NewService(store, auth.NewRBAC(), "")
	svc.SetAuditRecorder(spy)
	svc.SetLockoutTracker(auth.NewLockoutTracker(2, time.Minute))

	ctx := auth.WithLoginAuditContext(context.Background(), "10.0.0.5", "req-lock")
	for i := 0; i < 2; i++ {
		_, _ = svc.LoginWithTokenEndpoint(ctx, "bad-token")
	}
	if spy.lastAction != "auth.lockout" {
		t.Fatalf("action = %q, want auth.lockout", spy.lastAction)
	}
}

func TestAuditRecordPopulatesTopLevelAuthFields(t *testing.T) {
	repo := memory.NewAuditRepository()
	auditSvc := auditsvc.NewService(repo)
	ctx := context.Background()
	if err := auditSvc.Record(ctx, "10.0.0.3", "auth.login.failed", "auth/token", "failure", map[string]any{
		"auth_method":     "token",
		"source_ip":       "10.0.0.3",
		"client_identity": "anonymous",
		"request_id":      "req-abc",
		"failure_reason":  "invalid token",
	}); err != nil {
		t.Fatalf("Record() = %v", err)
	}
	entries, err := repo.List(ctx, repository.AuditListOptions{Limit: 1})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	entry := entries[0]
	if entry.AuthMethod != "token" || entry.RequestID != "req-abc" || entry.SourceIP != "10.0.0.3" {
		t.Fatalf("entry auth fields = %+v", entry)
	}
}