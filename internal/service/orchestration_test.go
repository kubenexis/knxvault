package service_test

import (
	"context"
	"testing"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/crypto"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func testCryptoKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestOrchestrationServiceRunKVRotation(t *testing.T) {
	cryptoSvc, err := crypto.NewService(testCryptoKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	secretRepo := memory.NewSecretRepository()
	rotationRepo := memory.NewRotationPolicyRepository()
	audit := auditsvc.NewService(memory.NewAuditRepository())
	kv := secretsengine.NewKVV2Engine(secretRepo, cryptoSvc)
	secretsSvc := service.NewSecretsService(kv, audit)

	policy := &domainsecrets.RotationPolicy{
		Path:      "app/db",
		Interval:  60,
		Generator: "random_password",
		Enabled:   true,
	}
	if err := rotationRepo.Save(context.Background(), policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	if _, err := secretsSvc.Put(context.Background(), "app/db", map[string]any{"password": "old"}, secretsengine.PutOptions{}); err != nil {
		t.Fatalf("put secret: %v", err)
	}

	rotationSvc := service.NewRotationService(rotationRepo, secretsSvc, audit, "")
	orch := service.NewOrchestrationService(rotationSvc, nil, nil, nil, "")

	policy.LastRotatedAt = time.Now().UTC().Add(-2 * time.Minute)
	_ = rotationRepo.Save(context.Background(), policy)

	result, err := orch.Run(context.Background(), time.Hour, 0)
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if result.KVRotated != 1 {
		t.Fatalf("KVRotated = %d, want 1", result.KVRotated)
	}
}
