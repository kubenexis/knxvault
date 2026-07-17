// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

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

func boolPtr(v bool) *bool {
	return &v
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

	if _, err := engine.RevokeLease(ctx, result.LeaseID); err != nil {
		t.Fatalf("RevokeLease() = %v", err)
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

func TestEngineMaxTTLAndNonRenewable(t *testing.T) {
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
		Name:       "limited",
		TTLSeconds: 60,
		MaxTTL:     120,
		Renewable:  boolPtr(false),
		CreationStatements: []string{
			"CREATE USER {{username}} PASSWORD '{{password}}';",
		},
	}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}

	_, err = engine.GenerateCredentials(ctx, database.CredsRequest{Role: "limited", TTLSecond: 3600})
	if err == nil {
		t.Fatal("expected max_ttl rejection")
	}

	result, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "limited", TTLSecond: 90})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	if result.TTLSeconds != 90 {
		t.Fatalf("TTLSeconds = %d want 90", result.TTLSeconds)
	}
	if result.MaxTTL != 120 {
		t.Fatalf("MaxTTL = %d want 120", result.MaxTTL)
	}
	if _, err := engine.Renew(ctx, result.LeaseID, 60); err == nil {
		t.Fatal("expected renew rejection for non-renewable lease")
	}
}

func TestEngineMaxLeasesQuota(t *testing.T) {
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
		Name:       "quota",
		TTLSeconds: 60,
		MaxLeases:  1,
		CreationStatements: []string{
			"CREATE USER {{username}} PASSWORD '{{password}}';",
		},
	}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}
	if _, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "quota"}); err != nil {
		t.Fatalf("first GenerateCredentials() = %v", err)
	}
	if _, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "quota"}); err == nil {
		t.Fatal("expected max_leases rejection")
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
