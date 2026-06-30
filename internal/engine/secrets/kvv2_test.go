package secrets_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestKVV2EngineRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	engine := secrets.NewKVV2Engine(memory.NewSecretRepository(), cryptoSvc)
	ctx := context.Background()

	result, err := engine.Put(ctx, "app/db", map[string]any{"password": "s3cret"}, secrets.PutOptions{TTL: "1h"})
	if err != nil {
		t.Fatalf("Put() = %v", err)
	}
	if result.Version != 1 {
		t.Fatalf("version = %d, want 1", result.Version)
	}

	got, err := engine.Get(ctx, "app/db")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if got.Data["password"] != "s3cret" {
		t.Fatalf("data = %v", got.Data)
	}
}
