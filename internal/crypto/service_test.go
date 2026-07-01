package crypto_test

import (
	"bytes"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
)

func testMasterKey() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func TestServiceSealOpen(t *testing.T) {
	svc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	plain := []byte(`{"secret":"value"}`)
	ct, dekEnc, err := svc.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := svc.Open(ct, dekEnc)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(plain, got) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestServiceRotateMasterKey(t *testing.T) {
	svc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	plain := []byte(`{"secret":"value"}`)
	ct, dekEnc, err := svc.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	newKey := bytes.Repeat([]byte{0x77}, 32)
	version, err := svc.RotateMasterKey(newKey)
	if err != nil {
		t.Fatalf("RotateMasterKey: %v", err)
	}
	if version != 2 {
		t.Fatalf("version = %d, want 2", version)
	}

	got, err := svc.Open(ct, dekEnc)
	if err != nil {
		t.Fatalf("Open after rotate: %v", err)
	}
	if !bytes.Equal(plain, got) {
		t.Fatal("data mismatch after rotate")
	}
}

func TestServiceRejectsInvalidMasterKey(t *testing.T) {
	if _, err := crypto.NewService([]byte("short")); err == nil {
		t.Fatal("expected error for invalid master key length")
	}
}

func TestServiceOpenRejectsTamperedCiphertext(t *testing.T) {
	svc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	plain := []byte(`{"k":"v"}`)
	ct, dekEnc, err := svc.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	ct[len(ct)-1] ^= 0xAA
	if _, err := svc.Open(ct, dekEnc); err == nil {
		t.Fatal("expected tampered ciphertext to fail Open")
	}
}

func TestServiceOpenRejectsTamperedDEK(t *testing.T) {
	svc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	plain := []byte(`{"k":"v"}`)
	ct, dekEnc, err := svc.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	dekEnc[len(dekEnc)-1] ^= 0x55
	if _, err := svc.Open(ct, dekEnc); err == nil {
		t.Fatal("expected tampered dek_enc to fail Open")
	}
}

func TestServiceReencryptDEKAfterRotation(t *testing.T) {
	svc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	dek, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	legacyEnc, err := svc.EncryptDEK(dek)
	if err != nil {
		t.Fatalf("EncryptDEK: %v", err)
	}
	if _, err := svc.RotateMasterKey(bytes.Repeat([]byte{0x88}, 32)); err != nil {
		t.Fatalf("RotateMasterKey: %v", err)
	}
	if !svc.DEKNeedsReencrypt(legacyEnc) {
		t.Fatal("legacy DEK should need reencrypt after rotation")
	}
	reenc, err := svc.ReencryptDEK(legacyEnc)
	if err != nil {
		t.Fatalf("ReencryptDEK: %v", err)
	}
	if reenc[0] != svc.ActiveKeyVersion() {
		t.Fatalf("reencrypted version = %d, want %d", reenc[0], svc.ActiveKeyVersion())
	}
	got, err := svc.DecryptDEK(reenc)
	if err != nil {
		t.Fatalf("DecryptDEK: %v", err)
	}
	if !bytes.Equal(dek, got) {
		t.Fatal("dek mismatch after reencrypt")
	}
}

func TestServiceDEKRoundTrip(t *testing.T) {
	svc, err := crypto.NewService(testMasterKey())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	dek, err := svc.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	enc, err := svc.EncryptDEK(dek)
	if err != nil {
		t.Fatalf("EncryptDEK: %v", err)
	}
	got, err := svc.DecryptDEK(enc)
	if err != nil {
		t.Fatalf("DecryptDEK: %v", err)
	}
	if !bytes.Equal(dek, got) {
		t.Fatal("dek mismatch")
	}
}
