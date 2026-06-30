package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestLeaseRepositoryCountActive(t *testing.T) {
	repo := memory.NewLeaseRepository()
	ctx := context.Background()
	now := time.Now().UTC()

	active := &secrets.Lease{
		ID: "l1", Path: "p1", RoleName: "r", Engine: "database",
		TTLSeconds: 3600, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Renewable: true,
	}
	expired := &secrets.Lease{
		ID: "l2", Path: "p2", RoleName: "r", Engine: "database",
		TTLSeconds: 60, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), Renewable: true,
	}
	revokedAt := now
	revoked := &secrets.Lease{
		ID: "l3", Path: "p3", RoleName: "r", Engine: "database",
		TTLSeconds: 3600, CreatedAt: now, ExpiresAt: now.Add(time.Hour), RevokedAt: &revokedAt, Renewable: true,
	}
	for _, lease := range []*secrets.Lease{active, expired, revoked} {
		if err := repo.Save(ctx, lease); err != nil {
			t.Fatalf("Save() = %v", err)
		}
	}

	count, err := repo.CountActive(ctx)
	if err != nil {
		t.Fatalf("CountActive() = %v", err)
	}
	if count != 1 {
		t.Fatalf("CountActive() = %d, want 1", count)
	}
}
