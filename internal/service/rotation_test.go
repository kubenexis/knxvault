package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestRotationServiceRunAll(t *testing.T) {
	key := make([]byte, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	secretRepo := memory.NewSecretRepository()
	policyRepo := memory.NewRotationPolicyRepository()
	kvEngine := secretsengine.NewKVV2Engine(secretRepo, cryptoSvc)
	secretsSvc := service.NewSecretsService(kvEngine, nil)
	rotationSvc := service.NewRotationService(policyRepo, secretsSvc, nil, "")

	ctx := context.Background()
	if err := rotationSvc.PutPolicy(ctx, &secrets.RotationPolicy{
		Path:      "app/token",
		Interval:  60,
		Generator: secrets.GeneratorRandomPassword,
	}); err != nil {
		t.Fatalf("PutPolicy() = %v", err)
	}
	if _, err := secretsSvc.Put(ctx, "app/token", map[string]any{"value": "old"}, secretsengine.PutOptions{}); err != nil {
		t.Fatalf("Put() = %v", err)
	}

	roles := memory.NewDatabaseRoleRepository()
	leases := memory.NewLeaseRepository()
	dbEngine := databaseengine.NewEngine(roles, leases, secretRepo, cryptoSvc)
	dbSvc := service.NewDatabaseService(dbEngine, nil)
	if err := dbSvc.SaveRole(ctx, databaseengine.RoleConfig{Name: "app", TTLSeconds: 30}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}
	creds, err := dbSvc.GenerateCredentials(ctx, databaseengine.CredsRequest{Role: "app"})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	lease, err := leases.Get(ctx, creds.LeaseID)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	lease.ExpiresAt = time.Now().UTC().Add(30 * time.Minute)
	if err := leases.Save(ctx, lease); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	policy, err := policyRepo.Get(ctx, "app/token")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	policy.LastRotatedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := policyRepo.Save(ctx, policy); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	result, err := rotationSvc.RunAll(ctx, time.Now().UTC(), dbSvc, time.Hour, 10)
	if err != nil {
		t.Fatalf("RunAll() = %v", err)
	}
	if result.KVRotated != 1 {
		t.Fatalf("KVRotated = %d, want 1", result.KVRotated)
	}
	if result.LeasesRenewed != 1 {
		t.Fatalf("LeasesRenewed = %d, want 1", result.LeasesRenewed)
	}
}