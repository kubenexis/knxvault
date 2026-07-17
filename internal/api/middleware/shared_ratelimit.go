// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/cache"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
)

// SharedRateLimiter enforces per-key RPM using cache.Store when available (cluster-wide).
type SharedRateLimiter struct {
	local   *RateLimiter
	store   cache.Store
	limit   int
	enabled bool
	prefix  string
}

// NewSharedRateLimiter wraps a local limiter with optional Valkey-backed counters.
func NewSharedRateLimiter(rpm int, enabled bool, store cache.Store) *SharedRateLimiter {
	return &SharedRateLimiter{
		local:   NewRateLimiter(rpm, enabled),
		store:   store,
		limit:   rpm,
		enabled: enabled,
		prefix:  "knxvault:ratelimit:",
	}
}

// Middleware enforces shared then local limits.
func (l *SharedRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if l == nil || !l.enabled {
			c.Next()
			return
		}
		key := c.ClientIP()
		if principal, ok := auth.PrincipalFromContext(c.Request.Context()); ok && principal.TokenID != "" {
			key = principal.TokenID
		}
		if l.store != nil && !l.allowShared(key) {
			metrics.IncRateLimited()
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error_code": common.ErrCodeForbidden,
				"message":    "rate limit exceeded",
			})
			return
		}
		// Always apply local limiter as a second layer (and when store is nil).
		if l.local != nil {
			l.local.Middleware()(c)
			return
		}
		c.Next()
	}
}

func (l *SharedRateLimiter) allowShared(key string) bool {
	// Minute bucket with atomic INCR when available (W76).
	bucket := time.Now().UTC().Format("200601021504")
	ck := fmt.Sprintf("%s%s:%s", l.prefix, bucket, key)
	ctx := context.Background()
	n := 0
	if inc, ok := l.store.(cache.IncrStore); ok {
		v, err := inc.Incr(ctx, ck, 2*time.Minute)
		if err == nil {
			n = int(v)
			return n <= l.limit
		}
	}
	if raw, ok := l.store.Get(ctx, ck); ok {
		n, _ = strconv.Atoi(string(raw))
	}
	n++
	if n > l.limit {
		return false
	}
	l.store.Set(ctx, ck, []byte(strconv.Itoa(n)), 2*time.Minute)
	return true
}

// Local returns the underlying process-local limiter (for tests).
func (l *SharedRateLimiter) Local() *RateLimiter {
	if l == nil {
		return nil
	}
	return l.local
}
