// Package cache provides optional Redis read-through caching (W33-01–02).
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

// MemoryStore is an in-process cache used when Redis is unavailable.
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

// RedisStore uses Redis when URL is set; falls back to memory on errors.
type RedisStore struct {
	redis    Store
	fallback Store
}

// NewRedisStore constructs a cache with optional Redis backend.
func NewRedisStore(url string) Store {
	fallback := NewMemoryStore()
	if url == "" {
		return fallback
	}
	if r, err := newMinimalRedis(url); err == nil {
		return &RedisStore{redis: r, fallback: fallback}
	}
	return fallback
}

func (r *RedisStore) Get(ctx context.Context, key string) ([]byte, bool) {
	if r.redis != nil {
		if v, ok := r.redis.Get(ctx, key); ok {
			return v, true
		}
	}
	return r.fallback.Get(ctx, key)
}

func (r *RedisStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) {
	if r.redis != nil {
		r.redis.Set(ctx, key, value, ttl)
	}
	r.fallback.Set(ctx, key, value, ttl)
}

func (r *RedisStore) Delete(ctx context.Context, key string) {
	if r.redis != nil {
		r.redis.Delete(ctx, key)
	}
	r.fallback.Delete(ctx, key)
}
