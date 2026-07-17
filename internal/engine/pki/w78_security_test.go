// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/url"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
	pkibackend "github.com/kubenexis/knxvault/internal/crypto/pki"
	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	pkiengine "github.com/kubenexis/knxvault/internal/engine/pki"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func newW78Engine(t *testing.T) *pkiengine.Engine {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatal(err)
	}
	eng := pkiengine.NewEngine(cryptoSvc, memory.NewCARepository(), memory.NewRevocationRepository())
	eng.SetBackend(pkibackend.NewNativeBackend())
	return eng
}

func TestW78_DefaultRoleIsNotUnconstrained(t *testing.T) {
	eng := newW78Engine(t)
	eng.SetPKIRoleRepository(memory.NewPKIRoleRepository())
	ctx := context.Background()
	if _, err := eng.CreateRoot(ctx, pkiengine.CreateRootRequest{Name: "root", CommonName: "Root", TTL: "8760h"}); err != nil {
		t.Fatal(err)
	}
	// Auto role uses _unconfigured.invalid — real DNS must be denied until admin updates domains.
	if _, err := eng.IssueCertificate(ctx, pkiengine.IssueRequest{
		Role: "root", CommonName: "app.example.com", DNSNames: []string{"app.example.com"}, TTL: "1h",
	}); err == nil {
		t.Fatal("expected default unconfigured role to deny real DNS")
	}
}

func TestW78_CSREmailURIRejectedForRestrictedRole(t *testing.T) {
	eng := newW78Engine(t)
	ctx := context.Background()
	if _, err := eng.CreateRoot(ctx, pkiengine.CreateRootRequest{Name: "root", CommonName: "Root", TTL: "8760h"}); err != nil {
		t.Fatal(err)
	}
	roleRepo := memory.NewPKIRoleRepository()
	if err := roleRepo.Save(ctx, &domainpki.Role{
		Name: "web", CAName: "root", AllowedDomains: []string{"example.com"}, AllowSubdomains: true,
	}); err != nil {
		t.Fatal(err)
	}
	eng.SetPKIRoleRepository(roleRepo)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://cluster.local/ns/kube-system/sa/default")
	csrTmpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "app.example.com"},
		DNSNames:       []string{"app.example.com"},
		EmailAddresses: []string{"admin@victim.com"},
		URIs:           []*url.URL{uri},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if _, err := eng.SignCSR(ctx, pkiengine.SignCSRRequest{Role: "web", CSRPEM: csrPEM, TTL: "30m"}); err == nil {
		t.Fatal("expected CSR with email/URI SANs to be rejected")
	}

	csrTmpl2 := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "app.example.com"},
		DNSNames: []string{"app.example.com"},
	}
	der2, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl2, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM2 := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der2}))
	if _, err := eng.SignCSR(ctx, pkiengine.SignCSRRequest{Role: "web", CSRPEM: csrPEM2, TTL: "30m"}); err != nil {
		t.Fatalf("dns-only CSR: %v", err)
	}
}

func TestW78_ImportCAKeyMustMatch(t *testing.T) {
	eng := newW78Engine(t)
	ctx := context.Background()
	root, err := eng.CreateRoot(ctx, pkiengine.CreateRootRequest{Name: "r1", CommonName: "R1", TTL: "8760h"})
	if err != nil {
		t.Fatal(err)
	}
	badKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(badKey)})
	if _, err := eng.ImportCA(ctx, pkiengine.ImportCARequest{
		Name: "imported", CertPEM: root.CertPEM, KeyPEM: string(badPEM),
	}); err == nil {
		t.Fatal("expected key mismatch rejection")
	}
}

func TestW78_ClientKeyUsageOnIssue(t *testing.T) {
	eng := newW78Engine(t)
	ctx := context.Background()
	if _, err := eng.CreateRoot(ctx, pkiengine.CreateRootRequest{Name: "root", CommonName: "Root", TTL: "8760h"}); err != nil {
		t.Fatal(err)
	}
	roleRepo := memory.NewPKIRoleRepository()
	if err := roleRepo.Save(ctx, &domainpki.Role{
		Name: "client", CAName: "root", AllowedDomains: []string{"example.com"}, AllowSubdomains: true, KeyUsage: domainpki.RoleUsageClient,
	}); err != nil {
		t.Fatal(err)
	}
	eng.SetPKIRoleRepository(roleRepo)
	leaf, err := eng.IssueCertificate(ctx, pkiengine.IssueRequest{
		Role: "client", CommonName: "user.example.com", DNSNames: []string{"user.example.com"}, TTL: "1h",
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(leaf.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			t.Fatal("client role must not include server auth EKU")
		}
	}
	found := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	if !found {
		t.Fatal("expected client auth EKU")
	}
}
