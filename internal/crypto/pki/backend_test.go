package pki_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os/exec"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto/openssl"
	pkibackend "github.com/kubenexis/knxvault/internal/crypto/pki"
)

func TestNativeBackendCreateRootStructure(t *testing.T) {
	backend := pkibackend.NewNativeBackend()
	if backend.Name() != "native" {
		t.Fatalf("Name() = %q, want native", backend.Name())
	}

	certPEM, keyPEM, err := backend.CreateRoot(context.Background(), pkibackend.RootRequest{
		CommonName: "Native Root",
		TTL:        24 * time.Hour,
		KeyBits:    2048,
	})
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}
	assertBackendOutput(t, backend, certPEM, keyPEM, true)
}

func TestNativeAndOpenSSLBackendParity(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}

	req := pkibackend.RootRequest{
		CommonName: "Parity Root",
		TTL:        48 * time.Hour,
		KeyBits:    2048,
	}
	ctx := context.Background()

	native := pkibackend.NewNativeBackend()
	nativeCert, nativeKey, err := native.CreateRoot(ctx, req)
	if err != nil {
		t.Fatalf("native CreateRoot() = %v", err)
	}

	ossl := pkibackend.NewOpenSSLBackend(openssl.New("", 30*time.Second))
	osslCert, osslKey, err := ossl.CreateRoot(ctx, req)
	if err != nil {
		t.Fatalf("openssl CreateRoot() = %v", err)
	}

	assertBackendOutput(t, native, nativeCert, nativeKey, true)
	assertOpenSSLRootStructure(t, ossl, osslCert, osslKey)
}

func assertOpenSSLRootStructure(t *testing.T, backend pkibackend.Backend, certPEM, keyPEM []byte) {
	t.Helper()

	cert, err := backend.ParseCertificate(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificate() = %v", err)
	}
	if cert.Subject.CommonName != "Parity Root" {
		t.Fatalf("common name = %q, want Parity Root", cert.Subject.CommonName)
	}
	if cert.Subject.Organization[0] != "KNXVault" {
		t.Fatalf("organization = %v, want KNXVault", cert.Subject.Organization)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("expected private key pem block")
	}
	switch keyBlock.Type {
	case "RSA PRIVATE KEY", "PRIVATE KEY":
	default:
		t.Fatalf("unexpected key pem type %q", keyBlock.Type)
	}
}

func assertBackendOutput(t *testing.T, backend pkibackend.Backend, certPEM, keyPEM []byte, wantCA bool) {
	t.Helper()
	compareCertStructure(t, backend, certPEM, keyPEM, wantCA)
}

func compareCertStructure(t *testing.T, backend pkibackend.Backend, certPEM, keyPEM []byte, wantCA bool) {
	t.Helper()

	cert, err := backend.ParseCertificate(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificate() = %v", err)
	}
	if cert.IsCA != wantCA {
		t.Fatalf("IsCA = %v, want %v", cert.IsCA, wantCA)
	}
	if cert.Subject.Organization[0] != "KNXVault" {
		t.Fatalf("organization = %v, want KNXVault", cert.Subject.Organization)
	}
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("signature = %v, want SHA256WithRSA", cert.SignatureAlgorithm)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		t.Fatal("expected RSA PRIVATE KEY pem block")
	}
}
