// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

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

func TestValkeyStoreFallbackWithoutURL(t *testing.T) {
	store := cache.NewValkeyStore("")
	ctx := context.Background()
	store.Set(ctx, "k2", []byte("fallback"), time.Minute)
	got, ok := store.Get(ctx, "k2")
	if !ok || string(got) != "fallback" {
		t.Fatalf("fallback Get() = %q ok=%v", got, ok)
	}
}

func TestValkeyStoreUsesMemoryWhenRemoteUnreachable(t *testing.T) {
	store := cache.NewValkeyStore("valkey://127.0.0.1:1")
	ctx := context.Background()
	store.Set(ctx, "probe", []byte("ok"), time.Minute)
	got, ok := store.Get(ctx, "probe")
	if !ok || string(got) != "ok" {
		t.Fatalf("Get() = %q ok=%v", got, ok)
	}
}
