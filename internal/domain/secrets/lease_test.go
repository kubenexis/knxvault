package secrets_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestLeaseActive(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	lease := secrets.Lease{
		ID:         "l_test",
		Path:       "database/creds/app/l_test",
		RoleName:   "app",
		Engine:     "database",
		TTLSeconds: 60,
		ExpiresAt:  now.Add(time.Minute),
	}
	if !lease.Active(now) {
		t.Fatal("expected active lease")
	}
	revoked := now
	lease.RevokedAt = &revoked
	if lease.Active(now) {
		t.Fatal("expected revoked lease to be inactive")
	}
}
