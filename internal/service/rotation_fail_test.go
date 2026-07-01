package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestRotationServiceRunDueReportsFailures(t *testing.T) {
	key := make([]byte, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	policyRepo := memory.NewRotationPolicyRepository()
	secretsRepo := memory.NewSecretRepository()
	kvEngine := secretsengine.NewKVV2Engine(secretsRepo, cryptoSvc)
	secretsSvc := service.NewSecretsService(kvEngine, nil)
	rotationSvc := service.NewRotationService(policyRepo, secretsSvc, nil, "")

	ctx := context.Background()
	if err := rotationSvc.PutPolicy(ctx, &secrets.RotationPolicy{
		Path:      "app/broken",
		Interval:  60,
		Generator: secrets.GeneratorScriptRef,
		ScriptRef: "rotate.sh",
	}); err != nil {
		t.Fatalf("PutPolicy() = %v", err)
	}
	policy, err := policyRepo.Get(ctx, "app/broken")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	policy.LastRotatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := policyRepo.Save(ctx, policy); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	rotated, err := rotationSvc.RunDue(ctx, time.Now().UTC())
	if err == nil {
		t.Fatal("expected rotation error for missing secret path")
	}
	if rotated != 0 {
		t.Fatalf("rotated = %d, want 0 on failure", rotated)
	}

	result, err := rotationSvc.RunAll(ctx, time.Now().UTC(), nil, time.Hour, 10)
	if err != nil {
		t.Fatalf("RunAll() = %v", err)
	}
	if len(result.Errors) == 0 {
		t.Fatal("expected partial errors in RunAll result")
	}
}