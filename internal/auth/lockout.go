package auth

import (
	"sync"
	"time"
)

// LockoutTracker tracks failed login attempts and temporary lockouts (W43-04).
type LockoutTracker struct {
	mu        sync.Mutex
	attempts  map[string]int
	locked    map[string]time.Time
	threshold int
	ttl       time.Duration
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
		attempts:  make(map[string]int),
		locked:    make(map[string]time.Time),
		threshold: threshold,
		ttl:       ttl,
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

// RecordFailure increments failures and locks when threshold exceeded.
func (t *LockoutTracker) RecordFailure(key string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.attempts[key]++
	if t.attempts[key] >= t.threshold {
		t.locked[key] = time.Now().Add(t.ttl)
		return true
	}
	return false
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
