// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package cache provides optional Valkey read-through caching (W33-01–02).
package cache

import (
	"context"
	"sync"
	"time"
)

// Store abstracts cache get/set/invalidate.
type Store interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration)
	Delete(ctx context.Context, key string)
}

// IncrStore optionally supports atomic increment (Valkey INCR / memory mutex).
// Used for cluster lockout and rate-limit counters (W76 residual).
type IncrStore interface {
	Store
	// Incr increments key by 1, sets TTL when key is new or on each bump when ttl > 0, returns new value.
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// MemoryStore is an in-process cache used when Valkey is unavailable.
type MemoryStore struct {
	mu    sync.RWMutex
	items map[string]entry
}

type entry struct {
	value []byte
	until time.Time
}

// NewMemoryStore constructs an in-memory cache fallback.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string]entry)}
}

func (s *MemoryStore) Get(_ context.Context, key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.items[key]
	if !ok || time.Now().After(e.until) {
		return nil, false
	}
	return e.value, true
}

func (s *MemoryStore) Set(_ context.Context, key string, value []byte, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	s.items[key] = entry{value: append([]byte(nil), value...), until: time.Now().Add(ttl)}
}

func (s *MemoryStore) Delete(_ context.Context, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
}

// Incr implements IncrStore with a process-local mutex.
func (s *MemoryStore) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now()
	e, ok := s.items[key]
	n := int64(0)
	if ok && now.Before(e.until) {
		// parse prior
		for _, b := range e.value {
			if b < '0' || b > '9' {
				n = 0
				break
			}
			n = n*10 + int64(b-'0')
		}
	}
	n++
	s.items[key] = entry{value: []byte(itoa(n)), until: now.Add(ttl)}
	return n, nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ValkeyStore uses a Valkey-compatible RESP server when URL is set; falls back to memory.
type ValkeyStore struct {
	remote   Store
	fallback Store
}

// NewValkeyStore constructs a cache with optional Valkey backend.
// URL format: valkey://host:port or host:port. Empty URL uses in-memory cache only.
func NewValkeyStore(url string) Store {
	fallback := NewMemoryStore()
	if url == "" {
		return fallback
	}
	if remote, err := newRESPClient(url); err == nil {
		return &ValkeyStore{remote: remote, fallback: fallback}
	}
	return fallback
}

func (v *ValkeyStore) Get(ctx context.Context, key string) ([]byte, bool) {
	if v.remote != nil {
		if raw, ok := v.remote.Get(ctx, key); ok {
			return raw, true
		}
	}
	return v.fallback.Get(ctx, key)
}

func (v *ValkeyStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) {
	if v.remote != nil {
		v.remote.Set(ctx, key, value, ttl)
	}
	v.fallback.Set(ctx, key, value, ttl)
}

func (v *ValkeyStore) Delete(ctx context.Context, key string) {
	if v.remote != nil {
		v.remote.Delete(ctx, key)
	}
	v.fallback.Delete(ctx, key)
}

// Incr prefers remote atomic INCR when available, else memory fallback.
func (v *ValkeyStore) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if v.remote != nil {
		if inc, ok := v.remote.(IncrStore); ok {
			n, err := inc.Incr(ctx, key, ttl)
			if err == nil {
				return n, nil
			}
		}
	}
	if fb, ok := v.fallback.(IncrStore); ok {
		return fb.Incr(ctx, key, ttl)
	}
	// Last resort non-atomic path.
	n := 0
	if raw, ok := v.Get(ctx, key); ok {
		for _, b := range raw {
			if b >= '0' && b <= '9' {
				n = n*10 + int(b-'0')
			}
		}
	}
	n++
	v.Set(ctx, key, []byte(itoa(int64(n))), ttl)
	return int64(n), nil
}
