package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/cache"
)

func TestMemoryStoreRoundTrip(t *testing.T) {
	store := cache.NewMemoryStore()
	ctx := context.Background()
	store.Set(ctx, "k1", []byte("value"), time.Minute)
	got, ok := store.Get(ctx, "k1")
	if !ok || string(got) != "value" {
		t.Fatalf("Get() = %q ok=%v", got, ok)
	}
	store.Delete(ctx, "k1")
	if _, ok := store.Get(ctx, "k1"); ok {
		t.Fatal("expected cache miss after delete")
	}
}

func TestRedisStoreFallbackWithoutURL(t *testing.T) {
	store := cache.NewRedisStore("")
	ctx := context.Background()
	store.Set(ctx, "k2", []byte("fallback"), time.Minute)
	got, ok := store.Get(ctx, "k2")
	if !ok || string(got) != "fallback" {
		t.Fatalf("fallback Get() = %q ok=%v", got, ok)
	}
}
