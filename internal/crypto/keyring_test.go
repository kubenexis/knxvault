package crypto_test

import (
	"bytes"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
)

func TestKeyRingRotateAndDecrypt(t *testing.T) {
	ring, err := crypto.NewKeyRing(testMasterKey())
	if err != nil {
		t.Fatalf("NewKeyRing() = %v", err)
	}
	dek := bytes.Repeat([]byte{0x11}, 32)
	legacyEnc, err := ring.EncryptDEK(dek)
	if err != nil {
		t.Fatalf("EncryptDEK() = %v", err)
	}

	newKey := bytes.Repeat([]byte{0x99}, 32)
	if err := ring.AddKey(2, newKey); err != nil {
		t.Fatalf("AddKey() = %v", err)
	}

	got, err := ring.DecryptDEK(legacyEnc)
	if err != nil {
		t.Fatalf("DecryptDEK(legacy) = %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("legacy dek mismatch")
	}

	newEnc, err := ring.EncryptDEK(dek)
	if err != nil {
		t.Fatalf("EncryptDEK(new) = %v", err)
	}
	if newEnc[0] != 2 {
		t.Fatalf("version prefix = %d, want 2", newEnc[0])
	}
	if !ring.DEKNeedsReencrypt(legacyEnc) {
		t.Fatal("legacy DEK should need reencrypt after rotation")
	}
	reenc, err := ring.ReencryptDEK(legacyEnc)
	if err != nil {
		t.Fatalf("ReencryptDEK() = %v", err)
	}
	if reenc[0] != 2 {
		t.Fatalf("reencrypted version = %d, want 2", reenc[0])
	}
}

func TestKeyRingDecryptLegacyWithoutVersionCollision(t *testing.T) {
	ring, err := crypto.NewKeyRing(testMasterKey())
	if err != nil {
		t.Fatalf("NewKeyRing() = %v", err)
	}
	dek := bytes.Repeat([]byte{0x22}, 32)
	enc, err := ring.EncryptDEK(dek)
	if err != nil {
		t.Fatalf("EncryptDEK() = %v", err)
	}
	if err := ring.AddKey(2, bytes.Repeat([]byte{0x99}, 32)); err != nil {
		t.Fatalf("AddKey() = %v", err)
	}
	got, err := ring.DecryptDEK(enc)
	if err != nil {
		t.Fatalf("DecryptDEK(legacy) = %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("legacy dek mismatch after adding version 2")
	}
}
