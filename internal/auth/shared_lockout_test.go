package auth_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/cache"
)

func TestSharedLockoutUsesCache(t *testing.T) {
	store := cache.NewMemoryStore()
	tr := auth.NewSharedLockoutTracker(2, time.Minute, store)
	key := auth.LockoutKey("token", "10.0.0.1")
	if tr.RecordFailure(key) {
		t.Fatal("not locked yet")
	}
	if !tr.RecordFailure(key) {
		t.Fatal("expected lock")
	}
	if !tr.IsLocked(key) {
		t.Fatal("expected locked")
	}
	// Second tracker sharing same store sees lock
	tr2 := auth.NewSharedLockoutTracker(2, time.Minute, store)
	if !tr2.IsLocked(key) {
		t.Fatal("shared store should propagate lock")
	}
	tr.Clear(key)
	if tr2.IsLocked(key) {
		t.Fatal("clear should remove shared lock")
	}
}
