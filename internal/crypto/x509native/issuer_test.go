package x509native_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto/x509native"
)

func TestCreateRootProducesValidCA(t *testing.T) {
	certPEM, keyPEM, err := x509native.CreateRoot("Test Root CA", 24*time.Hour, 2048)
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}
	assertCertificateStructure(t, certPEM, keyPEM, true)
}

func TestCreateIntermediateAndIssueLeaf(t *testing.T) {
	rootCert, rootKey, err := x509native.CreateRoot("Test Root", 48*time.Hour, 2048)
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}

	intCert, intKey, err := x509native.CreateIntermediate(rootCert, rootKey, "Test Intermediate", 24*time.Hour, 2048)
	if err != nil {
		t.Fatalf("CreateIntermediate() = %v", err)
	}
	assertCertificateStructure(t, intCert, intKey, true)

	leafCert, leafKey, err := x509native.IssueCertificate(
		intCert, intKey, "example.com",
		[]string{"example.com", "www.example.com"},
		nil,
		12*time.Hour,
		2048,
	)
	if err != nil {
		t.Fatalf("IssueCertificate() = %v", err)
	}
	assertCertificateStructure(t, leafCert, leafKey, false)

	cert, err := x509native.ParseCertificate(leafCert)
	if err != nil {
		t.Fatalf("ParseCertificate() = %v", err)
	}
	if len(cert.DNSNames) != 2 {
		t.Fatalf("DNSNames = %v, want 2 entries", cert.DNSNames)
	}

	if err := x509native.VerifyChain(leafCert, [][]byte{intCert, rootCert}); err != nil {
		t.Fatalf("VerifyChain() = %v", err)
	}
}

func assertCertificateStructure(t *testing.T, certPEM, keyPEM []byte, wantCA bool) {
	t.Helper()

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatal("expected CERTIFICATE pem block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() = %v", err)
	}
	if cert.Subject.Organization[0] != "KNXVault" {
		t.Fatalf("organization = %v, want KNXVault", cert.Subject.Organization)
	}
	if cert.IsCA != wantCA {
		t.Fatalf("IsCA = %v, want %v", cert.IsCA, wantCA)
	}
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("signature = %v, want SHA256WithRSA", cert.SignatureAlgorithm)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		t.Fatal("expected RSA PRIVATE KEY pem block")
	}
}
