package acme_test

import (
	"crypto/ecdsa"
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
	if ek.D.Cmp(orig.D) != 0 {
		t.Fatal("D mismatch after PEM round-trip")
	}
}

func TestParseAccountKeyPEMRejectsGarbage(t *testing.T) {
	if _, err := acme.ParseAccountKeyPEM([]byte("not-pem")); err == nil {
		t.Fatal("expected error")
	}
}
