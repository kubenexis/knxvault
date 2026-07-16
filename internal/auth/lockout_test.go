package auth_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestLoginLockoutKeyPrefersClientIdentity(t *testing.T) {
	key := auth.LoginLockoutKey("kubernetes", auth.LoginAuditContext{
		SourceIP:       "10.0.0.5",
		ClientIdentity: "system:serviceaccount:ns:sa",
	})
	want := auth.LockoutKey("kubernetes", "system:serviceaccount:ns:sa")
	if key != want {
		t.Fatalf("LoginLockoutKey() = %q, want %q", key, want)
	}
	ipOnly := auth.LoginLockoutKey("kubernetes", auth.LoginAuditContext{SourceIP: "10.0.0.5"})
	if ipOnly != auth.LockoutKey("kubernetes", "10.0.0.5") {
		t.Fatalf("ip-only key = %q", ipOnly)
	}
}

func TestLockoutTrackerThreshold(t *testing.T) {
	tracker := auth.NewLockoutTracker(3, time.Minute)
	key := auth.LockoutKey("oidc", "user@example.com")

	for i := 0; i < 2; i++ {
		if tracker.IsLocked(key) {
			t.Fatal("expected not locked before threshold")
		}
		if locked := tracker.RecordFailure(key); locked {
			t.Fatal("expected not locked on early failures")
		}
	}
	if !tracker.RecordFailure(key) {
		t.Fatal("expected lock on third failure")
	}
	if !tracker.IsLocked(key) {
		t.Fatal("expected locked after threshold")
	}
	tracker.RecordSuccess(key)
	if tracker.IsLocked(key) {
		t.Fatal("expected unlock after success")
	}
}
