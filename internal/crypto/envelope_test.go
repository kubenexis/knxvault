// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

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

func TestEnvelopeUniqueNonces(t *testing.T) {
	key := bytes.Repeat([]byte{0xCD}, 32)
	env, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	plain := []byte("same plaintext")
	first, err := env.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	second, err := env.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("expected unique ciphertext for identical plaintext (random nonce)")
	}
}

func TestEnvelopeRejectsTamperedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0xEF}, 32)
	env, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	enc, err := env.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := append([]byte(nil), enc...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := env.Decrypt(tampered); err == nil {
		t.Fatal("expected GCM authentication failure for tampered ciphertext")
	}
}

func TestEnvelopeRejectsWrongKey(t *testing.T) {
	keyA := bytes.Repeat([]byte{0x01}, 32)
	keyB := bytes.Repeat([]byte{0x02}, 32)
	envA, err := crypto.NewEnvelope(keyA)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	envB, err := crypto.NewEnvelope(keyB)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	enc, err := envA.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := envB.Decrypt(enc); err == nil {
		t.Fatal("expected decrypt failure with wrong key")
	}
}

func TestEnvelopeRejectsTruncatedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	env, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if _, err := env.Decrypt([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for ciphertext too short")
	}
}
