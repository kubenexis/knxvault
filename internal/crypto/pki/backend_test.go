// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

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

func TestNativeBackendIssueLeaf(t *testing.T) {
	backend := pkibackend.NewNativeBackend()
	ctx := context.Background()
	caCert, caKey, err := backend.CreateRoot(ctx, pkibackend.RootRequest{
		CommonName: "Issue Root",
		TTL:        48 * time.Hour,
		KeyBits:    2048,
	})
	if err != nil {
		t.Fatalf("CreateRoot() = %v", err)
	}
	leafCert, leafKey, err := backend.IssueCertificate(ctx, pkibackend.IssueRequest{
		CACertPEM:  caCert,
		CAKeyPEM:   caKey,
		CommonName: "leaf.example.com",
		DNSNames:   []string{"leaf.example.com"},
		TTL:        24 * time.Hour,
		KeyBits:    2048,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() = %v", err)
	}
	assertBackendOutput(t, backend, leafCert, leafKey, false)
}

func assertBackendOutput(t *testing.T, backend pkibackend.Backend, certPEM, keyPEM []byte, wantCA bool) {
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
