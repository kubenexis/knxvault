// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

type putAtomicSecretRepo struct {
	*memory.SecretRepository
	putAtomicCalls int
}

func (r *putAtomicSecretRepo) PutAtomic(ctx context.Context, sv *secrets.SecretVersion, cas *int, max int) (int, error) {
	r.putAtomicCalls++
	return r.SecretRepository.PutAtomic(ctx, sv, cas, max)
}

func TestEngineStoreSecretUsesPutAtomic(t *testing.T) {
	cryptoSvc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	roles := memory.NewDatabaseRoleRepository()
	leases := memory.NewLeaseRepository()
	secretsRepo := &putAtomicSecretRepo{SecretRepository: memory.NewSecretRepository()}
	engine := database.NewEngine(roles, leases, secretsRepo, cryptoSvc)

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

	if _, err := engine.GenerateCredentials(ctx, database.CredsRequest{Role: "readonly"}); err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	if secretsRepo.putAtomicCalls != 1 {
		t.Fatalf("PutAtomic calls = %d, want 1", secretsRepo.putAtomicCalls)
	}

	leaseList, err := leases.List(ctx)
	if err != nil || len(leaseList) != 1 {
		t.Fatalf("leases = %v, %v", leaseList, err)
	}
	if _, err := engine.Renew(ctx, leaseList[0].ID, 120); err != nil {
		t.Fatalf("Renew() = %v", err)
	}
	if secretsRepo.putAtomicCalls != 2 {
		t.Fatalf("PutAtomic calls after renew = %d, want 2", secretsRepo.putAtomicCalls)
	}
	_ = time.Now()
}
