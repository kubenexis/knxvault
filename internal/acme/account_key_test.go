package acme_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/kubenexis/knxvault/internal/acme"
)

func TestAccountKeyPEMRoundTrip(t *testing.T) {
	key, err := acme.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := acme.MarshalAccountKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := acme.ParseAccountKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	ek, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("type %T", parsed)
	}
	orig := key.(*ecdsa.PrivateKey)
	if !ek.Equal(orig) {
		t.Fatal("key mismatch after PEM round-trip")
	}
}

func TestAccountKeyRSARoundTrip(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := acme.MarshalAccountKeyPEM(k)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := acme.ParseAccountKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Fatalf("type %T", parsed)
	}
}

func TestAccountKeyPKCS8ECDSA(t *testing.T) {
	k, err := acme.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	parsed, err := acme.ParseAccountKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("type %T", parsed)
	}
}

func TestMarshalAccountKeyNil(t *testing.T) {
	if _, err := acme.MarshalAccountKeyPEM(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseAccountKeyPEMRejectsGarbage(t *testing.T) {
	if _, err := acme.ParseAccountKeyPEM([]byte("not-pem")); err == nil {
		t.Fatal("expected error")
	}
	// unsupported type
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	if _, err := acme.ParseAccountKeyPEM(b); err == nil {
		t.Fatal("expected unsupported type")
	}
}
