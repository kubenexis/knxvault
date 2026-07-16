package auth

import (
	"sync"
	"time"
)

// LockoutTracker tracks failed login attempts and temporary lockouts (W43-04).
type LockoutTracker struct {
	mu         sync.Mutex
	attempts   map[string]int
	locked     map[string]time.Time
	threshold  int
	ttl        time.Duration
	maxEntries int
}

// NewLockoutTracker constructs a lockout tracker.
func NewLockoutTracker(threshold int, ttl time.Duration) *LockoutTracker {
	if threshold <= 0 {
		threshold = 5
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &LockoutTracker{
		attempts:   make(map[string]int),
		locked:     make(map[string]time.Time),
		threshold:  threshold,
		ttl:        ttl,
		maxEntries: 50000,
	}
}

// Key builds a lockout identity key.
func LockoutKey(authMethod, subjectOrIP string) string {
	return authMethod + ":" + subjectOrIP
}

// IsLocked reports whether the identity is currently locked out.
func (t *LockoutTracker) IsLocked(key string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	until, ok := t.locked[key]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(t.locked, key)
		delete(t.attempts, key)
		return false
	}
	return true
}

// IsLockedAny reports whether any of the keys is locked out (W50-18).
func (t *LockoutTracker) IsLockedAny(keys ...string) bool {
	for _, k := range keys {
		if t.IsLocked(k) {
			return true
		}
	}
	return false
}

func (t *LockoutTracker) purgeExpiredLocked(now time.Time) {
	for key, until := range t.locked {
		if now.After(until) {
			delete(t.locked, key)
			delete(t.attempts, key)
		}
	}
}

// RecordFailure increments failures and locks when threshold exceeded.
func (t *LockoutTracker) RecordFailure(key string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.purgeExpiredLocked(time.Now())
	if _, ok := t.attempts[key]; !ok && t.maxEntries > 0 && len(t.attempts) >= t.maxEntries {
		// Bound memory under credential-stuffing: drop half of non-locked attempt counters.
		t.evictAttemptsLocked()
	}
	t.attempts[key]++
	if t.attempts[key] >= t.threshold {
		t.locked[key] = time.Now().Add(t.ttl)
		return true
	}
	return false
}

func (t *LockoutTracker) evictAttemptsLocked() {
	// Prefer keeping keys that are currently locked.
	for k := range t.attempts {
		if _, locked := t.locked[k]; locked {
			continue
		}
		delete(t.attempts, k)
		if len(t.attempts) < t.maxEntries/2 {
			return
		}
	}
}

// RecordSuccess clears failure counters for the identity.
func (t *LockoutTracker) RecordSuccess(key string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.attempts, key)
	delete(t.locked, key)
}

// Clear removes lockout state (admin break-glass).
func (t *LockoutTracker) Clear(key string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.attempts, key)
	delete(t.locked, key)
}
