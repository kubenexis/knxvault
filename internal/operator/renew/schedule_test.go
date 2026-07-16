package renew

import (
	"testing"
	"time"
)

func TestNeedsRenew(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rb := 30 * 24 * time.Hour

	if !NeedsRenew("", rb, now) {
		t.Fatal("empty notAfter should renew")
	}
	// Far future — no renew.
	far := now.Add(90 * 24 * time.Hour).Format(time.RFC3339)
	if NeedsRenew(far, rb, now) {
		t.Fatal("far future should not renew")
	}
	// Within renewBefore window.
	soon := now.Add(10 * 24 * time.Hour).Format(time.RFC3339)
	if !NeedsRenew(soon, rb, now) {
		t.Fatal("within renewBefore should renew")
	}
	// Invalid parse → renew.
	if !NeedsRenew("not-a-date", rb, now) {
		t.Fatal("invalid date should renew")
	}
}

func TestRequeueAfter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rb := 30 * 24 * time.Hour

	if RequeueAfter("", rb, now) != 0 {
		t.Fatal("empty notAfter requeue 0")
	}
	// Deadline in ~12h → requeue under 24h cap.
	notAfter := now.Add(rb + 12*time.Hour).Format(time.RFC3339)
	d := RequeueAfter(notAfter, rb, now)
	if d < 11*time.Hour || d > 13*time.Hour {
		t.Fatalf("requeue = %v, want ~12h", d)
	}
	// Cap at 24h when far.
	far := now.Add(200 * 24 * time.Hour).Format(time.RFC3339)
	if RequeueAfter(far, rb, now) != 24*time.Hour {
		t.Fatalf("want 24h cap, got %v", d)
	}
}

func TestParseDuration(t *testing.T) {
	t.Parallel()
	d, err := ParseDuration("", DefaultDuration)
	if err != nil || d != DefaultDuration {
		t.Fatalf("got %v %v", d, err)
	}
	d, err = ParseDuration("72h", DefaultDuration)
	if err != nil || d != 72*time.Hour {
		t.Fatalf("got %v %v", d, err)
	}
}

func TestIsClientUsage(t *testing.T) {
	t.Parallel()
	if IsClientUsage([]string{"server auth"}) {
		t.Fatal("server only")
	}
	if !IsClientUsage([]string{"client auth"}) {
		t.Fatal("client auth")
	}
}
