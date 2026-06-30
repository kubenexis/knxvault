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
