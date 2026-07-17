// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestSanitizeDetailsRedactsSensitiveKeys(t *testing.T) {
	in := map[string]any{
		"role":     "readonly",
		"password": "s3cret",
		"nested": map[string]any{
			"connection_url": "mysql://admin:pass@db:3306/app",
		},
	}
	out := audit.SanitizeDetails(in)
	if out["password"] != "[REDACTED]" {
		t.Fatalf("password = %v", out["password"])
	}
	nested := out["nested"].(map[string]any)
	if nested["connection_url"] != "[REDACTED]" {
		t.Fatalf("connection_url = %v", nested["connection_url"])
	}
	if out["role"] != "readonly" {
		t.Fatalf("role = %v", out["role"])
	}
	in2 := map[string]any{"client_token": "t", "jwt": "j", "secret_id": "s", "master_key": "m"}
	out2 := audit.SanitizeDetails(in2)
	for _, k := range []string{"client_token", "jwt", "secret_id", "master_key"} {
		if out2[k] != "[REDACTED]" {
			t.Fatalf("%s = %v", k, out2[k])
		}
	}
}

func TestRejectSensitiveDetails(t *testing.T) {
	err := audit.RejectSensitiveDetails(map[string]any{"password": "x"})
	if err == nil {
		t.Fatal("expected rejection for sensitive key")
	}
	err = audit.RejectSensitiveDetails(map[string]any{"note": "mysql://admin:pass@db:3306/app"})
	if err == nil {
		t.Fatal("expected rejection for credential-like string")
	}
	if err := audit.RejectSensitiveDetails(map[string]any{"role": "readonly"}); err != nil {
		t.Fatalf("benign details: %v", err)
	}
}

func TestServiceRecordRedactsDetails(t *testing.T) {
	repo := memory.NewAuditRepository()
	svc := audit.NewService(repo)
	ctx := context.Background()

	if err := svc.Record(ctx, "tester", "database.creds.generate", "secrets/database/creds/readonly", "success", map[string]any{
		"password": "generated",
	}); err != nil {
		t.Fatalf("Record() = %v", err)
	}
	entries, err := repo.List(ctx, repository.AuditListOptions{})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Details["password"] != "[REDACTED]" {
		t.Fatalf("details = %#v", entries[0].Details)
	}
}
