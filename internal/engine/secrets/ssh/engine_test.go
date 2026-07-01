package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/crypto"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	sshengine "github.com/kubenexis/knxvault/internal/engine/secrets/ssh"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	gossh "golang.org/x/crypto/ssh"
)

func testCrypto(t *testing.T) *crypto.Service {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	svc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	return svc
}

func storeCAKey(t *testing.T, ctx context.Context, secrets *memory.SecretRepository, cryptoSvc *crypto.Service, path string) {
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
		ID:        uuid.New(),
		Path:      path,
		Version:   1,
		DataEnc:   dataEnc,
		DEKEnc:    dekEnc,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveVersion() = %v", err)
	}
}

func TestEngineGenerateRenewRevoke(t *testing.T) {
	ctx := context.Background()
	cryptoSvc := testCrypto(t)
	roles := memory.NewSSHRoleRepository()
	leases := memory.NewLeaseRepository()
	secrets := memory.NewSecretRepository()
	engine := sshengine.NewEngine(roles, leases, secrets, cryptoSvc)

	caPath := "ssh/ca/test"
	storeCAKey(t, ctx, secrets, cryptoSvc, caPath)

	if err := engine.SaveRole(ctx, sshengine.RoleConfig{
		Name:        "ops",
		TTLSeconds:  600,
		CAKeyPath:   caPath,
		DefaultUser: "deploy",
	}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}

	result, err := engine.GenerateCredentials(ctx, sshengine.CredsRequest{Role: "ops"})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	if result.Username != "deploy" || result.PrivateKey == "" || result.SignedKey == "" {
		t.Fatalf("unexpected creds: %+v", result)
	}
	if !strings.Contains(result.SignedKey, "cert-authority") && !strings.HasPrefix(strings.TrimSpace(result.SignedKey), "ssh-ed25519") {
		// OpenSSH authorized_keys format for certs starts with key type
		if !strings.Contains(result.SignedKey, "ssh-ed25519") {
			t.Fatalf("signed_key = %q", result.SignedKey)
		}
	}

	renewed, err := engine.Renew(ctx, result.LeaseID, 300)
	if err != nil {
		t.Fatalf("Renew() = %v", err)
	}
	if renewed.TTLSeconds != 300 {
		t.Fatalf("ttl = %d, want 300", renewed.TTLSeconds)
	}

	if err := engine.RevokeLease(ctx, result.LeaseID); err != nil {
		t.Fatalf("RevokeLease() = %v", err)
	}
	lease, err := leases.Get(ctx, result.LeaseID)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if lease.RevokedAt == nil {
		t.Fatal("expected revoked lease")
	}
}

func TestEngineRejectsDisallowedUser(t *testing.T) {
	ctx := context.Background()
	cryptoSvc := testCrypto(t)
	roles := memory.NewSSHRoleRepository()
	leases := memory.NewLeaseRepository()
	secrets := memory.NewSecretRepository()
	engine := sshengine.NewEngine(roles, leases, secrets, cryptoSvc)

	caPath := "ssh/ca/test"
	storeCAKey(t, ctx, secrets, cryptoSvc, caPath)
	if err := engine.SaveRole(ctx, sshengine.RoleConfig{
		Name:         "restricted",
		TTLSeconds:   300,
		CAKeyPath:    caPath,
		AllowedUsers: []string{"allowed"},
	}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}
	if _, err := engine.GenerateCredentials(ctx, sshengine.CredsRequest{
		Role:     "restricted",
		Username: "other",
	}); err == nil {
		t.Fatal("expected username validation error")
	}
}
