package openssl

import (
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen indicates the OpenSSL circuit breaker is open.
var ErrCircuitOpen = errors.New("openssl circuit breaker open")

// Breaker short-circuits OpenSSL calls after consecutive failures.
type Breaker struct {
	mu            sync.Mutex
	failures      int
	threshold     int
	cooldown      time.Duration
	openUntil     time.Time
	onStateChange func(open bool)
}

// NewBreaker constructs a circuit breaker.
func NewBreaker(threshold int, cooldown time.Duration) *Breaker {
	if threshold <= 0 {
		threshold = 3
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &Breaker{threshold: threshold, cooldown: cooldown}
}

// SetOnStateChange registers a callback when the breaker opens or closes.
func (b *Breaker) SetOnStateChange(fn func(open bool)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onStateChange = fn
}

// Allow reports whether a call may proceed.
func (b *Breaker) Allow() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() || time.Now().After(b.openUntil) {
		return nil
	}
	return ErrCircuitOpen
}

// RecordSuccess resets failure count.
func (b *Breaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	wasOpen := !b.openUntil.IsZero() && time.Now().Before(b.openUntil)
	b.failures = 0
	b.openUntil = time.Time{}
	if wasOpen && b.onStateChange != nil {
		b.onStateChange(false)
	}
}

// RecordFailure increments failures and may open the breaker.
func (b *Breaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	if b.failures < b.threshold {
		return
	}
	b.openUntil = time.Now().Add(b.cooldown)
	b.failures = 0
	if b.onStateChange != nil {
		b.onStateChange(true)
	}
}

// Open reports whether the breaker is currently open.
func (b *Breaker) Open() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.openUntil.IsZero() && time.Now().Before(b.openUntil)
}
