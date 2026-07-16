package auth

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/kubenexis/knxvault/internal/cache"
)

// SharedLockoutTracker is a cluster-aware lockout using cache.Store (Valkey when configured).
// Falls back to in-process maps when cache is nil/unavailable.
type SharedLockoutTracker struct {
	local     *LockoutTracker
	store     cache.Store
	threshold int
	ttl       time.Duration
	prefix    string
}

// NewSharedLockoutTracker builds a lockout tracker that prefers shared cache counters.
func NewSharedLockoutTracker(threshold int, ttl time.Duration, store cache.Store) *SharedLockoutTracker {
	return &SharedLockoutTracker{
		local:     NewLockoutTracker(threshold, ttl),
		store:     store,
		threshold: threshold,
		ttl:       ttl,
		prefix:    "knxvault:lockout:",
	}
}

// AsLockoutTracker returns the local tracker for interfaces that need *LockoutTracker.
// Prefer Shared methods when cluster-wide behavior is required.
func (t *SharedLockoutTracker) AsLockoutTracker() *LockoutTracker {
	if t == nil {
		return nil
	}
	return t.local
}

// IsLocked reports lockout using shared store when available.
func (t *SharedLockoutTracker) IsLocked(key string) bool {
	if t == nil {
		return false
	}
	if t.store != nil {
		if raw, ok := t.store.Get(context.Background(), t.prefix+"locked:"+key); ok && len(raw) > 0 {
			until, err := strconv.ParseInt(string(raw), 10, 64)
			if err == nil && time.Now().Unix() < until {
				return true
			}
			t.store.Delete(context.Background(), t.prefix+"locked:"+key)
		}
	}
	return t.local.IsLocked(key)
}

// IsLockedAny reports whether any key is locked.
func (t *SharedLockoutTracker) IsLockedAny(keys ...string) bool {
	for _, k := range keys {
		if t.IsLocked(k) {
			return true
		}
	}
	return false
}

// RecordFailure increments failures cluster-wide when store is set.
func (t *SharedLockoutTracker) RecordFailure(key string) bool {
	if t == nil {
		return false
	}
	if t.store != nil {
		ck := t.prefix + "fail:" + key
		n := t.incr(ck)
		if n >= t.threshold {
			until := time.Now().Add(t.ttl).Unix()
			t.store.Set(context.Background(), t.prefix+"locked:"+key, []byte(fmt.Sprintf("%d", until)), t.ttl)
			return true
		}
		return false
	}
	return t.local.RecordFailure(key)
}

// RecordSuccess clears counters.
func (t *SharedLockoutTracker) RecordSuccess(key string) {
	if t == nil {
		return
	}
	if t.store != nil {
		t.store.Delete(context.Background(), t.prefix+"fail:"+key)
		t.store.Delete(context.Background(), t.prefix+"locked:"+key)
	}
	t.local.RecordSuccess(key)
}

// Clear removes lockout state.
func (t *SharedLockoutTracker) Clear(key string) {
	t.RecordSuccess(key)
}

func (t *SharedLockoutTracker) incr(key string) int {
	// Get-modify-set (best-effort without native INCR).
	n := 0
	if raw, ok := t.store.Get(context.Background(), key); ok {
		n, _ = strconv.Atoi(string(raw))
	}
	n++
	t.store.Set(context.Background(), key, []byte(strconv.Itoa(n)), t.ttl)
	return n
}
