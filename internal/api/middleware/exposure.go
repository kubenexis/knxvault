// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/cache"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

const (
	exposureSignatureHeader = "X-KNXVault-Exposure-Signature"
	exposureTimestampHeader = "X-KNXVault-Exposure-Timestamp"
	// MaxExposureSkew is the max absolute clock skew accepted for signed exposure reports (W50-24).
	MaxExposureSkew = 5 * time.Minute
	// exposureReplayKeyPrefix namespaces shared cache keys for HA replay (W80-06).
	exposureReplayKeyPrefix = "knxvault:exposure:replay:"
)

// ExposureReplayStore marks a replay key as seen. Returns false if the key was already present.
// Used for HA-safe exposure report anti-replay when backed by Valkey (W80-06).
type ExposureReplayStore interface {
	MarkSeen(ctx context.Context, key string, ttl time.Duration) bool
}

// ExposureSigning verifies HMAC signatures on exposure reports.
type ExposureSigning struct {
	key     []byte
	seenMu  sync.Mutex
	seen    map[string]time.Time
	seenTTL time.Duration
	// maxSkew is absolute |now-ts| allowed; 0 uses MaxExposureSkew.
	maxSkew time.Duration
	// replay is optional shared store (Valkey). When set, preferred over process-local map.
	replay ExposureReplayStore
}

// NewExposureSigning constructs exposure report signing middleware.
func NewExposureSigning(key string) *ExposureSigning {
	if key == "" {
		return nil
	}
	return &ExposureSigning{
		key:     []byte(key),
		seen:    make(map[string]time.Time),
		seenTTL: 5 * time.Minute,
		maxSkew: MaxExposureSkew,
	}
}

// SetReplayStore installs a shared (HA) replay store. Nil keeps process-local only.
func (s *ExposureSigning) SetReplayStore(store ExposureReplayStore) {
	if s == nil {
		return
	}
	s.replay = store
}

func (s *ExposureSigning) markSeen(ctx context.Context, signature string) bool {
	ttl := s.seenTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if s.replay != nil {
		return s.replay.MarkSeen(ctx, signature, ttl)
	}
	now := time.Now()
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	for sig, at := range s.seen {
		if now.Sub(at) > ttl {
			delete(s.seen, sig)
		}
	}
	if _, ok := s.seen[signature]; ok {
		return false
	}
	s.seen[signature] = now
	return true
}

// SignExposurePayload computes the HMAC for body + timestamp (tests / clients).
// MAC = HMAC-SHA256(key, timestamp + "\n" + body).
func SignExposurePayload(key, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Middleware validates the exposure report signature when configured.
func (s *ExposureSigning) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s == nil || len(s.key) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error_code": string(common.ErrCodeUnauthorized),
				"message":    "exposure signing not configured",
			})
			return
		}
		signature := c.GetHeader(exposureSignatureHeader)
		if signature == "" {
			abortUnauthorized(c, "exposure signature required")
			return
		}
		tsHeader := c.GetHeader(exposureTimestampHeader)
		if tsHeader == "" {
			abortUnauthorized(c, "exposure timestamp required")
			return
		}
		tsUnix, err := strconv.ParseInt(tsHeader, 10, 64)
		if err != nil {
			abortUnauthorized(c, "invalid exposure timestamp")
			return
		}
		skew := s.maxSkew
		if skew <= 0 {
			skew = MaxExposureSkew
		}
		ts := time.Unix(tsUnix, 0)
		if d := time.Since(ts); d > skew || d < -skew {
			abortUnauthorized(c, "exposure timestamp outside allowed skew")
			return
		}
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			abortUnauthorized(c, "read body failed")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		expected := SignExposurePayload(string(s.key), tsHeader, body)
		if !hmac.Equal([]byte(signature), []byte(expected)) {
			abortUnauthorized(c, "invalid exposure signature")
			return
		}
		// Replay key includes timestamp so same body at different times is distinct.
		replayKey := tsHeader + ":" + signature
		if !s.markSeen(c.Request.Context(), replayKey) {
			abortUnauthorized(c, "exposure report replay detected")
			return
		}
		c.Next()
	}
}

// CacheExposureReplayStore uses cache.IncrStore (Valkey or memory) for HA-safe replay (W80-06).
// First MarkSeen returns true (Incr==1); subsequent calls return false.
type CacheExposureReplayStore struct {
	store cache.Store
}

// NewCacheExposureReplayStore wraps a cache.Store. Returns nil when store is nil.
func NewCacheExposureReplayStore(store cache.Store) *CacheExposureReplayStore {
	if store == nil {
		return nil
	}
	return &CacheExposureReplayStore{store: store}
}

// MarkSeen implements ExposureReplayStore.
func (s *CacheExposureReplayStore) MarkSeen(ctx context.Context, key string, ttl time.Duration) bool {
	if s == nil || s.store == nil {
		return true
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	full := exposureReplayKeyPrefix + key
	if inc, ok := s.store.(cache.IncrStore); ok {
		n, err := inc.Incr(ctx, full, ttl)
		if err != nil {
			// Fail open to process-local is not available here; fail closed on shared path errors.
			return false
		}
		return n == 1
	}
	// Non-atomic fallback: Get then Set (still better than nothing for single-process Valkey stubs).
	if _, ok := s.store.Get(ctx, full); ok {
		return false
	}
	s.store.Set(ctx, full, []byte("1"), ttl)
	return true
}
