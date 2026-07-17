// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/crypto"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	sshengine "github.com/kubenexis/knxvault/internal/engine/secrets/ssh"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
	gossh "golang.org/x/crypto/ssh"
)

func storeSSHCAKey(t *testing.T, ctx context.Context, secrets *memory.SecretRepository, cryptoSvc *crypto.Service, path string) {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() = %v", err)
	}
	block, err := gossh.MarshalPrivateKey(caPriv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey() = %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"private_key": string(pem.EncodeToMemory(block))})
	dataEnc, dekEnc, err := cryptoSvc.Seal(payload)
	if err != nil {
		t.Fatalf("Seal() = %v", err)
	}
	if err := secrets.SaveVersion(ctx, &domainsecrets.SecretVersion{
		ID: uuid.New(), Path: path, Version: 1, DataEnc: dataEnc, DEKEnc: dekEnc, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveVersion() = %v", err)
	}
}

func TestOrchestrationServiceRenewsSSHLeases(t *testing.T) {
	key := testCryptoKey()
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	leases := memory.NewLeaseRepository()
	roles := memory.NewSSHRoleRepository()
	secrets := memory.NewSecretRepository()
	sshEngine := sshengine.NewEngine(roles, leases, secrets, cryptoSvc)
	sshSvc := service.NewSSHService(sshEngine, nil)
	ctx := context.Background()
	caPath := "ssh/ca/test"
	storeSSHCAKey(t, ctx, secrets, cryptoSvc, caPath)

	if err := sshSvc.SaveRole(ctx, sshengine.RoleConfig{Name: "ops", TTLSeconds: 120, CAKeyPath: caPath, DefaultUser: "deploy"}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}
	result, err := sshSvc.GenerateCredentials(ctx, sshengine.CredsRequest{Role: "ops"})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	lease, err := leases.Get(ctx, result.LeaseID)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	lease.ExpiresAt = time.Now().UTC().Add(30 * time.Minute)
	if err := leases.Save(ctx, lease); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	orch := service.NewOrchestrationService(nil, nil, sshSvc, nil, "")
	run, err := orch.Run(ctx, time.Hour, 45*time.Minute, 0)
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if run.SSHRenewed != 1 {
		t.Fatalf("SSHRenewed = %d, want 1", run.SSHRenewed)
	}
}
