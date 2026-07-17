// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/repository/memory"
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

func TestCARepositoryRoundTrip(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewCARepository()
	ca := validRootCA()

	if err := repo.Save(ctx, ca); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	got, err := repo.GetByName(ctx, ca.Name)
	if err != nil {
		t.Fatalf("GetByName() = %v", err)
	}
	if got.ID != ca.ID {
		t.Fatalf("ID = %v, want %v", got.ID, ca.ID)
	}

	list, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len(List()) = %d, want 1", len(list))
	}
}
