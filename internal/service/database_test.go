// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"
	"time"

	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestDatabaseServiceGenerateRenewRevoke(t *testing.T) {
	cryptoSvc := testCrypto(t)
	roles := memory.NewDatabaseRoleRepository()
	leases := memory.NewLeaseRepository()
	secrets := memory.NewSecretRepository()
	engine := databaseengine.NewEngine(roles, leases, secrets, cryptoSvc)
	svc := service.NewDatabaseService(engine, testAudit())
	ctx := context.Background()

	cfg := databaseengine.RoleConfig{
		Name:       "readonly",
		TTLSeconds: 60,
		CreationStatements: []string{
			"CREATE USER {{username}} PASSWORD '{{password}}';",
		},
	}
	if err := svc.SaveRole(ctx, cfg); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}

	role, err := svc.GetRole(ctx, "readonly")
	if err != nil {
		t.Fatalf("GetRole() = %v", err)
	}
	if role.Name != "readonly" {
		t.Fatalf("role name = %q", role.Name)
	}

	result, err := svc.GenerateCredentials(ctx, databaseengine.CredsRequest{Role: "readonly"})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	if result.LeaseID == "" {
		t.Fatal("expected lease id")
	}

	renewed, err := svc.Renew(ctx, result.LeaseID, 120)
	if err != nil {
		t.Fatalf("Renew() = %v", err)
	}
	if renewed.TTLSeconds != 60 {
		t.Fatalf("TTLSeconds = %d, want 60", renewed.TTLSeconds)
	}

	if _, err := svc.Revoke(ctx, result.LeaseID); err != nil {
		t.Fatalf("Revoke() = %v", err)
	}
}

func TestDatabaseServiceCleanupExpired(t *testing.T) {
	cryptoSvc := testCrypto(t)
	roles := memory.NewDatabaseRoleRepository()
	leases := memory.NewLeaseRepository()
	secrets := memory.NewSecretRepository()
	engine := databaseengine.NewEngine(roles, leases, secrets, cryptoSvc)
	svc := service.NewDatabaseService(engine, testAudit())
	ctx := context.Background()

	if err := svc.SaveRole(ctx, databaseengine.RoleConfig{Name: "app", TTLSeconds: 30}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}
	result, err := svc.GenerateCredentials(ctx, databaseengine.CredsRequest{Role: "app"})
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

	count, err := svc.CleanupExpired(ctx, 10)
	if err != nil {
		t.Fatalf("CleanupExpired() = %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
}
