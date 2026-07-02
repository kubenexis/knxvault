package auth_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
)

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
