package database_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestEngineManagedModeExecutesSQL(t *testing.T) {
	cryptoSvc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	roles := memory.NewDatabaseRoleRepository()
	leases := memory.NewLeaseRepository()
	secretRepo := memory.NewSecretRepository()
	engine := database.NewEngine(roles, leases, secretRepo, cryptoSvc)
	ctx := context.Background()

	dbFile := filepath.Join(t.TempDir(), "managed.db")
	connURL := "sqlite:" + dbFile
	adminPayload, _ := json.Marshal(map[string]any{"connection_url": connURL})
	adminEnc, adminDEK, err := cryptoSvc.Seal(adminPayload)
	if err != nil {
		t.Fatalf("Seal() = %v", err)
	}
	if err := secretRepo.SaveVersion(ctx, &secrets.SecretVersion{
		ID: uuid.New(), Path: "database/admin/test", Version: 1,
		DataEnc: adminEnc, DEKEnc: adminDEK,
	}); err != nil {
		t.Fatalf("SaveVersion() = %v", err)
	}

	if err := engine.SaveRole(ctx, database.RoleConfig{
		Name:                 "managed-role",
		TTLSeconds:           300,
		ExecutionMode:        secrets.ExecutionModeManaged,
		AdminCredentialsPath: "database/admin/test",
		CreationStatements:   []string{"CREATE TABLE IF NOT EXISTS vault_users (username TEXT PRIMARY KEY);"},
		RevocationStatements: []string{"DROP TABLE IF EXISTS vault_users;"},
	}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}

	result, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "managed-role"})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	if result.LeaseID == "" {
		t.Fatal("expected lease")
	}

	if err := engine.RevokeLease(ctx, result.LeaseID); err != nil {
		t.Fatalf("RevokeLease() = %v", err)
	}
}
