package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/google/uuid"
	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/crypto"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	sshengine "github.com/kubenexis/knxvault/internal/engine/secrets/ssh"
	"github.com/kubenexis/knxvault/internal/infra/leader"
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

func TestJobRunnerRenewsSSHLeasesOnLeadership(t *testing.T) {
	key := make([]byte, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	roles := memory.NewSSHRoleRepository()
	leases := memory.NewLeaseRepository()
	secrets := memory.NewSecretRepository()
	engine := sshengine.NewEngine(roles, leases, secrets, cryptoSvc)
	sshSvc := service.NewSSHService(engine, nil)
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
	before := lease.ExpiresAt
	lease.ExpiresAt = time.Now().UTC().Add(30 * time.Minute)
	if err := leases.Save(ctx, lease); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	t.Setenv("KNXVAULT_JOB_CERT_RENEW_INTERVAL", "20ms")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	runCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	runner := app.NewJobRunner(&staticElector{leader: true}, leader.NewMonitor(), nil, sshSvc, nil, nil, nil, nil, leases, cfg, zap.NewNop())
	runner.Start(runCtx)
	<-runCtx.Done()

	lease, err = leases.Get(ctx, result.LeaseID)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if !lease.ExpiresAt.After(before) {
		t.Fatalf("expires_at = %v, want after %v", lease.ExpiresAt, before)
	}
}