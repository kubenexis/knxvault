// Copyright The KNXVault Authors.
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
