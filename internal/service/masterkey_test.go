package service_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestMasterKeyServiceRotateAndReencrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	cas := memory.NewCARepository()
	secretRepo := memory.NewSecretRepository()
	svc := service.NewMasterKeyService(cryptoSvc, cas, secretRepo)
	ctx := context.Background()

	newKey := bytes.Repeat([]byte{0x77}, 32)
	result, err := svc.Rotate(ctx, service.RotateRequest{NewKeyBase64: base64.StdEncoding.EncodeToString(newKey)})
	if err != nil {
		t.Fatalf("Rotate() = %v", err)
	}
	if result.KeyVersion != 2 {
		t.Fatalf("KeyVersion = %d, want 2", result.KeyVersion)
	}

	// simulate pre-rotation dek by sealing with version 1 only path
	legacyRing, _ := crypto.NewKeyRing(key)
	legacyDEK, _ := legacyRing.EncryptDEK(bytes.Repeat([]byte{0x01}, 32))
	ca := &pki.CA{
		ID: uuid.New(), Name: "root", Type: pki.CATypeRoot, Serial: "01",
		CertPEM:       "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		PrivateKeyEnc: []byte{1}, DEKEnc: legacyDEK, Status: pki.CAStatusActive,
	}
	if err := cas.Save(ctx, ca); err != nil {
		t.Fatalf("Save(ca) = %v", err)
	}
	reenc, err := svc.ReencryptDEKs(ctx, 10)
	if err != nil {
		t.Fatalf("ReencryptDEKs() = %v", err)
	}
	if reenc.CAs != 1 {
		t.Fatalf("CAs = %d, want 1", reenc.CAs)
	}
}
