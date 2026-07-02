package service_test

import (
	"context"
	"testing"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/crypto"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestLabelsForPathDoesNotAudit(t *testing.T) {
	key := testCryptoKey()
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	auditRepo := memory.NewAuditRepository()
	auditSvc := auditsvc.NewService(auditRepo)
	svc := service.NewSecretsService(
		secretsengine.NewKVV2Engine(memory.NewSecretRepository(), cryptoSvc),
		auditSvc,
	)
	ctx := context.Background()
	if _, err := svc.Put(ctx, "app/x", map[string]any{"v": "1"}, secretsengine.PutOptions{
		Labels: map[string]string{"owner": "team-a"},
	}); err != nil {
		t.Fatalf("Put() = %v", err)
	}
	labels, err := svc.LabelsForPath(ctx, "app/x")
	if err != nil {
		t.Fatalf("LabelsForPath() = %v", err)
	}
	if labels["owner"] != "team-a" {
		t.Fatalf("labels = %v", labels)
	}
	entries, err := auditRepo.List(ctx, repository.AuditListOptions{})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	for _, e := range entries {
		if e.Action == "secret.metadata" {
			t.Fatal("LabelsForPath should not emit secret.metadata audit events")
		}
	}
}
