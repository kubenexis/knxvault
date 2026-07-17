package pki_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
	pkibackend "github.com/kubenexis/knxvault/internal/crypto/pki"
	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestEngineCreateRootAndIssue(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	engine := pkiengine.NewEngine(cryptoSvc,
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

func testPKIEngine(t *testing.T) *pkiengine.Engine {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	engine := pkiengine.NewEngine(cryptoSvc,
		memory.NewCARepository(),
		memory.NewRevocationRepository(),
	)
	engine.SetIssuedCertRepository(memory.NewIssuedCertRepository())
	engine.SetPKIRoleRepository(memory.NewPKIRoleRepository())
	return engine
}

func TestEngineCreateIntermediate(t *testing.T) {
	engine := testPKIEngine(t)
	ctx := context.Background()

	root, err := engine.CreateRoot(ctx, pkiengine.CreateRootRequest{
		Name:       "root",
		CommonName: "KNXVault Root",
		TTL:        "30d",
	})
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}

	intermediate, err := engine.CreateIntermediate(ctx, pkiengine.CreateIntermediateRequest{
		ParentName: "root",
		Name:       "intermediate",
		CommonName: "KNXVault Intermediate",
		TTL:        "14d",
	})
	if err != nil {
		t.Fatalf("CreateIntermediate() = %v", err)
	}
	if intermediate.CertPEM == "" {
		t.Fatal("expected intermediate cert pem")
	}

	ca, err := engine.GetCA(ctx, intermediate.ID)
	if err != nil {
		t.Fatalf("GetCA() = %v", err)
	}
	if ca.Type != domainpki.CATypeIntermediate {
		t.Fatalf("ca type = %q", ca.Type)
	}
	if ca.ParentID == nil || *ca.ParentID != root.ID {
		t.Fatalf("parent id = %v, want %s", ca.ParentID, root.ID)
	}
}

func TestEngineRevokeAndGenerateCRL(t *testing.T) {
	engine := testPKIEngine(t)
	engine.SetBackend(pkibackend.NewNativeBackend())
	ctx := context.Background()

	root, err := engine.CreateRoot(ctx, pkiengine.CreateRootRequest{
		Name:       "crl-root",
		CommonName: "CRL Root",
		TTL:        "30d",
	})
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}

	leaf, err := engine.IssueCertificate(ctx, pkiengine.IssueRequest{
		Role:       "crl-root",
		CommonName: "revoke.example.com",
		TTL:        "7d",
		DNSNames:   []string{"revoke.example.com"},
	})
	if err != nil {
		t.Fatalf("IssueCertificate() = %v", err)
	}

	if err := engine.Revoke(ctx, root.ID, leaf.Serial, "keyCompromise"); err != nil {
		t.Fatalf("Revoke() = %v", err)
	}

	crlPEM, err := engine.GenerateCRL(ctx, root.ID)
	if err != nil {
		t.Fatalf("GenerateCRL() = %v", err)
	}
	if crlPEM == "" || !strings.Contains(crlPEM, "BEGIN X509 CRL") {
		t.Fatalf("unexpected CRL: %q", crlPEM)
	}
}

func TestEngineRoleBasedIssuance(t *testing.T) {
	engine := testPKIEngine(t)
	ctx := context.Background()

	root, err := engine.CreateRoot(ctx, pkiengine.CreateRootRequest{
		Name:       "role-root",
		CommonName: "Role Root",
		TTL:        "30d",
	})
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}
	_ = root

	roleRepo := memory.NewPKIRoleRepository()
	if err := roleRepo.Save(ctx, &domainpki.Role{
		Name:            "web",
		CAName:          "role-root",
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		MaxTTLSeconds:   3600,
		KeyUsage:        domainpki.RoleUsageServer,
	}); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	engine.SetPKIRoleRepository(roleRepo)

	if _, err := engine.IssueCertificate(ctx, pkiengine.IssueRequest{
		Role:       "web",
		CommonName: "app.example.com",
		TTL:        "30m",
		DNSNames:   []string{"app.example.com"},
	}); err != nil {
		t.Fatalf("IssueCertificate() = %v", err)
	}

	if _, err := engine.IssueCertificate(ctx, pkiengine.IssueRequest{
		Role:       "web",
		CommonName: "evil.other.com",
		TTL:        "2h",
		DNSNames:   []string{"evil.other.com"},
	}); err == nil {
		t.Fatal("expected domain validation error")
	}

	if _, err := engine.IssueCertificate(ctx, pkiengine.IssueRequest{
		Role:       "web",
		CommonName: "app.example.com",
		TTL:        "48h",
		DNSNames:   []string{"app.example.com"},
	}); err == nil {
		t.Fatal("expected ttl exceeds role maximum error")
	}
}

func TestEngineGenerateCRLIncludesRevokedEntry(t *testing.T) {
	engine := testPKIEngine(t)
	engine.SetBackend(pkibackend.NewNativeBackend())
	ctx := context.Background()

	root, err := engine.CreateRoot(ctx, pkiengine.CreateRootRequest{
		Name:       "crl-entry-root",
		CommonName: "CRL Entry Root",
		TTL:        "30d",
	})
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}
	leaf, err := engine.IssueCertificate(ctx, pkiengine.IssueRequest{
		Role:       "crl-entry-root",
		CommonName: "leaf.example.com",
		TTL:        "7d",
		DNSNames:   []string{"leaf.example.com"},
	})
	if err != nil {
		t.Fatalf("IssueCertificate() = %v", err)
	}
	if err := engine.Revoke(ctx, root.ID, leaf.Serial, "affiliationChanged"); err != nil {
		t.Fatalf("Revoke() = %v", err)
	}

	crlPEM, err := engine.GenerateCRL(ctx, root.ID)
	if err != nil {
		t.Fatalf("GenerateCRL() = %v", err)
	}
	block, _ := pem.Decode([]byte(crlPEM))
	if block == nil {
		t.Fatal("failed to decode CRL PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList() = %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("revoked entries = %d, want 1", len(crl.RevokedCertificateEntries))
	}
}

func TestEngineSignCSREnforcesRoleDomains(t *testing.T) {
	engine := testPKIEngine(t)
	engine.SetBackend(pkibackend.NewNativeBackend())
	ctx := context.Background()
	if _, err := engine.CreateRoot(ctx, pkiengine.CreateRootRequest{
		Name: "csr-root", CommonName: "CSR Root", TTL: "30d",
	}); err != nil {
		t.Fatal(err)
	}
	roleRepo := memory.NewPKIRoleRepository()
	if err := roleRepo.Save(ctx, &domainpki.Role{
		Name: "web", CAName: "csr-root",
		AllowedDomains: []string{"example.com"}, AllowSubdomains: true,
		MaxTTLSeconds: 3600, KeyUsage: domainpki.RoleUsageServer,
	}); err != nil {
		t.Fatal(err)
	}
	engine.SetPKIRoleRepository(roleRepo)

	// Build a CSR for evil.other.com
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "evil.other.com"},
		DNSNames: []string{"evil.other.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if _, err := engine.SignCSR(ctx, pkiengine.SignCSRRequest{Role: "web", CSRPEM: string(csrPEM), TTL: "30m"}); err == nil {
		t.Fatal("expected domain rejection for CSR")
	}

	// Allowed CSR
	csrDER2, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "app.example.com"},
		DNSNames: []string{"app.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER2})
	res, err := engine.SignCSR(ctx, pkiengine.SignCSRRequest{Role: "web", CSRPEM: string(csrPEM2), TTL: "30m"})
	if err != nil {
		t.Fatalf("allowed CSR: %v", err)
	}
	if res.CertPEM == "" {
		t.Fatal("empty cert")
	}
}
