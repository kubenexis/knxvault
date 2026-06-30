package pki_test

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/crypto/openssl"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestEngineCreateRootAndIssue(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	engine := pkiengine.NewEngine(
		openssl.New("", 30*time.Second),
		cryptoSvc,
		memory.NewCARepository(),
		memory.NewRevocationRepository(),
	)

	ctx := context.Background()
	root, err := engine.CreateRoot(ctx, pkiengine.CreateRootRequest{
		Name:       "test-root",
		CommonName: "KNXVault Test Root",
		TTL:        "30d",
	})
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}
	if root.CertPEM == "" {
		t.Fatal("expected cert pem")
	}

	leaf, err := engine.IssueCertificate(ctx, pkiengine.IssueRequest{
		Role:       "test-root",
		CommonName: "example.com",
		TTL:        "7d",
		DNSNames:   []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("IssueCertificate() = %v", err)
	}
	if leaf.CertPEM == "" || leaf.PrivateKeyPEM == "" {
		t.Fatal("expected leaf cert and key")
	}
}
