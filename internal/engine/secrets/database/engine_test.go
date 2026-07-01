package database_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func testMasterKey() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func TestEngineGenerateAndRevoke(t *testing.T) {
	cryptoSvc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	roles := memory.NewDatabaseRoleRepository()
	leases := memory.NewLeaseRepository()
	secrets := memory.NewSecretRepository()
	engine := database.NewEngine(roles, leases, secrets, cryptoSvc)

	ctx := context.Background()
	if err := engine.SaveRole(ctx, database.RoleConfig{
		Name:       "readonly",
		TTLSeconds: 60,
		CreationStatements: []string{
			"CREATE USER {{username}} PASSWORD '{{password}}';",
		},
		RevocationStatements: []string{
			"DROP USER {{username}};",
		},
	}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}

	result, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "readonly"})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	if result.LeaseID == "" || result.Username == "" || result.Password == "" {
		t.Fatal("expected generated credentials")
	}
	if len(result.Statements) != 1 {
		t.Fatalf("len(Statements) = %d, want 1", len(result.Statements))
	}

	renewed, err := engine.Renew(ctx, result.LeaseID, 120)
	if err != nil {
		t.Fatalf("Renew() = %v", err)
	}
	if renewed.TTLSeconds != 60 {
		t.Fatalf("TTLSeconds = %d, want 60", renewed.TTLSeconds)
	}

	revokeResult, err := engine.RevokeLease(ctx, result.LeaseID)
	if err != nil {
		t.Fatalf("RevokeLease() = %v", err)
	}
	if revokeResult.LeaseID != result.LeaseID {
		t.Fatalf("LeaseID = %q, want %q", revokeResult.LeaseID, result.LeaseID)
	}
	if len(revokeResult.RevocationStatements) != 1 {
		t.Fatalf("len(RevocationStatements) = %d, want 1", len(revokeResult.RevocationStatements))
	}
	lease, err := leases.Get(ctx, result.LeaseID)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if lease.RevokedAt == nil {
		t.Fatal("expected lease revoked")
	}
}

func TestEngineSaveRoleRejectsSecretConfig(t *testing.T) {
	cryptoSvc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	engine := database.NewEngine(memory.NewDatabaseRoleRepository(), memory.NewLeaseRepository(), memory.NewSecretRepository(), cryptoSvc)
	err = engine.SaveRole(context.Background(), database.RoleConfig{
		Name:           "readonly",
		TTLSeconds:     60,
		UsernamePrefix: "v-",
		Config: map[string]any{
			"connection_url": "mysql://admin:pass@db:3306/app",
		},
	})
	if err == nil {
		t.Fatal("expected validation error for secret config")
	}
}

func TestEngineSaveRoleAdminCredentialsPath(t *testing.T) {
	cryptoSvc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	roles := memory.NewDatabaseRoleRepository()
	engine := database.NewEngine(roles, memory.NewLeaseRepository(), memory.NewSecretRepository(), cryptoSvc)
	ctx := context.Background()
	if err := engine.SaveRole(ctx, database.RoleConfig{
		Name:                 "readonly",
		TTLSeconds:           60,
		UsernamePrefix:       "v-",
		AdminCredentialsPath: "database/admin/prod-db",
		Config: map[string]any{
			"db_type": "mysql",
		},
	}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}
	role, err := roles.Get(ctx, "readonly")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if role.AdminCredentialsPath != "database/admin/prod-db" {
		t.Fatalf("AdminCredentialsPath = %q", role.AdminCredentialsPath)
	}
}

func TestEngineCleanupExpired(t *testing.T) {
	cryptoSvc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	roles := memory.NewDatabaseRoleRepository()
	leases := memory.NewLeaseRepository()
	secrets := memory.NewSecretRepository()
	engine := database.NewEngine(roles, leases, secrets, cryptoSvc)

	ctx := context.Background()
	_ = engine.SaveRole(ctx, database.RoleConfig{Name: "app", TTLSeconds: 30})

	result, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "app"})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}

	lease, err := leases.Get(ctx, result.LeaseID)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	lease.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := leases.Save(ctx, lease); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	revoked, err := engine.CleanupExpired(ctx, 10)
	if err != nil {
		t.Fatalf("CleanupExpired() = %v", err)
	}
	if revoked != 1 {
		t.Fatalf("revoked = %d, want 1", revoked)
	}
}
