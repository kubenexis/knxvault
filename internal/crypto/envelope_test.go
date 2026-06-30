package crypto_test

import (
	"bytes"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	env, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}

	plain := []byte(`{"username":"admin"}`)
	enc, err := env.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := env.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plain, got) {
		t.Fatalf("round-trip mismatch: %q vs %q", plain, got)
	}
}

func TestEnvelopeRejectsShortKey(t *testing.T) {
	_, err := crypto.NewEnvelope([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short master key")
	}
}
