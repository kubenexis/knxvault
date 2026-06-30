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
	result, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "app", TTLSecond: 3600})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	if result.TTLSeconds != 60 {
		t.Fatalf("TTLSeconds = %d, want 60", result.TTLSeconds)
	}
}
