package pki_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/pki"
)

func validRootCA() *pki.CA {
	return &pki.CA{
		ID:            uuid.New(),
		Name:          "root",
		Type:          pki.CATypeRoot,
		Serial:        "01",
		CertPEM:       "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		PrivateKeyEnc: []byte{1, 2, 3},
		DEKEnc:        []byte{4, 5, 6},
		Status:        pki.CAStatusActive,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour),
	}
}

func TestCAValidateRoot(t *testing.T) {
	if err := validRootCA().Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestCAValidateIntermediateRequiresParent(t *testing.T) {
	ca := validRootCA()
	ca.Type = pki.CATypeIntermediate
	if err := ca.Validate(); err == nil {
		t.Fatal("expected error without parent_id")
	}
}
