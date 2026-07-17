// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestIssuedCertRepositoryListExpiring(t *testing.T) {
	repo := memory.NewIssuedCertRepository()
	ctx := context.Background()
	caID := uuid.New()
	now := time.Now().UTC()

	expiring := &domainpki.IssuedCertificate{
		ID:         uuid.New(),
		CAID:       caID,
		Role:       "web",
		Serial:     "aa",
		CommonName: "expiring.example.com",
		TTLSeconds: 3600,
		IssuedAt:   now.Add(-48 * time.Hour),
		ExpiresAt:  now.Add(-time.Hour),
		AutoRenew:  true,
	}
	fresh := &domainpki.IssuedCertificate{
		ID:         uuid.New(),
		CAID:       caID,
		Role:       "web",
		Serial:     "bb",
		CommonName: "fresh.example.com",
		TTLSeconds: 3600,
		IssuedAt:   now,
		ExpiresAt:  now.Add(30 * 24 * time.Hour),
		AutoRenew:  true,
	}
	manual := &domainpki.IssuedCertificate{
		ID:         uuid.New(),
		CAID:       caID,
		Role:       "web",
		Serial:     "cc",
		CommonName: "manual.example.com",
		TTLSeconds: 3600,
		IssuedAt:   now.Add(-48 * time.Hour),
		ExpiresAt:  now.Add(-time.Hour),
		AutoRenew:  false,
	}
	for _, cert := range []*domainpki.IssuedCertificate{expiring, fresh, manual} {
		if err := repo.Save(ctx, cert); err != nil {
			t.Fatalf("Save() = %v", err)
		}
	}

	list, err := repo.ListExpiring(ctx, now.Add(72*time.Hour), 10)
	if err != nil {
		t.Fatalf("ListExpiring() = %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len(ListExpiring) = %d, want 1", len(list))
	}
	if list[0].Serial != expiring.Serial {
		t.Fatalf("serial = %q, want %q", list[0].Serial, expiring.Serial)
	}
}
