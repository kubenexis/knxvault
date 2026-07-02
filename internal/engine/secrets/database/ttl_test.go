package database_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestGenerateCredentialsCapsTTL(t *testing.T) {
	cryptoSvc, err := crypto.NewService(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	roles := memory.NewDatabaseRoleRepository()
	engine := database.NewEngine(roles, memory.NewLeaseRepository(), memory.NewSecretRepository(), cryptoSvc)
	ctx := context.Background()
	if err := engine.SaveRole(ctx, database.RoleConfig{Name: "app", TTLSeconds: 60}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}
	_, err = engine.GenerateCredentials(ctx, database.CredsRequest{Role: "app", TTLSecond: 3600})
	if err == nil {
		t.Fatal("expected max_ttl rejection when requested ttl exceeds role max")
	}
	result, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "app", TTLSecond: 30})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	if result.TTLSeconds != 30 {
		t.Fatalf("TTLSeconds = %d, want 30", result.TTLSeconds)
	}
}
