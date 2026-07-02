package app

import (
	"testing"
	"time"
)

func TestLeaseRenewGrace(t *testing.T) {
	if g := leaseRenewGrace(0); g != 24*time.Hour {
		t.Fatalf("zero = %v, want 24h", g)
	}
	if g := leaseRenewGrace(72 * time.Hour); g != 24*time.Hour {
		t.Fatalf("72h = %v, want capped 24h", g)
	}
	if g := leaseRenewGrace(6 * time.Hour); g != 6*time.Hour {
		t.Fatalf("6h = %v, want 6h", g)
	}
}