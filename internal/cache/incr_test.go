// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/cache"
)

func TestMemoryStoreIncrAtomic(t *testing.T) {
	s := cache.NewMemoryStore()
	ctx := context.Background()
	n1, err := s.Incr(ctx, "k", time.Minute)
	if err != nil || n1 != 1 {
		t.Fatalf("n1=%d err=%v", n1, err)
	}
	n2, err := s.Incr(ctx, "k", time.Minute)
	if err != nil || n2 != 2 {
		t.Fatalf("n2=%d err=%v", n2, err)
	}
}
