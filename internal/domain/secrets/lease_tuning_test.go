package secrets_test

import (
	"testing"
	"time"

	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
)

func TestLeaseWarningsBelowTenPercentTTL(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(5 * time.Minute)
	warnings := domainsecrets.LeaseWarnings(now, expiresAt, 3600)
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want one entry", warnings)
	}
}

func TestLeaseWarningsHealthyTTL(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(30 * time.Minute)
	if warnings := domainsecrets.LeaseWarnings(now, expiresAt, 3600); len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
}

func TestResolveRenewTTLCapsAtMax(t *testing.T) {
	tuning := domainsecrets.LeaseTuning{MaxTTL: 3600}
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(30 * time.Minute)
	got := tuning.ResolveRenewTTL(7200, 1800, now, expiresAt)
	if got > 3600 {
		t.Fatalf("ResolveRenewTTL() = %d, want <= 3600", got)
	}
}