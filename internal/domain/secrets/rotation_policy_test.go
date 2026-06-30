package secrets_test

import (
	"testing"
	"time"

	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestRotationPolicyDue(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	policy := domainsecrets.RotationPolicy{
		Path:          "app/db",
		Interval:      3600,
		Generator:     domainsecrets.GeneratorRandomPassword,
		Enabled:       true,
		LastRotatedAt: now.Add(-2 * time.Hour),
	}
	if !policy.Due(now) {
		t.Fatal("expected policy to be due")
	}
	policy.LastRotatedAt = now.Add(-30 * time.Minute)
	if policy.Due(now) {
		t.Fatal("expected policy not due yet")
	}
}
