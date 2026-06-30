package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
)

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

// RateLimiter enforces per-client request limits (W19).
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	limit    float64
	interval time.Duration
	enabled  bool
}

// NewRateLimiter constructs a token-bucket rate limiter.
func NewRateLimiter(requestsPerMinute int, enabled bool) *RateLimiter {
	if requestsPerMinute <= 0 {
		requestsPerMinute = 300
	}
	return &RateLimiter{
		buckets:  make(map[string]*bucket),
		limit:    float64(requestsPerMinute),
		interval: time.Minute,
		enabled:  enabled,
	}
}

// Middleware returns a Gin handler that enforces rate limits.
func (l *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if l == nil || !l.enabled {
			c.Next()
			return
		}
		key := c.ClientIP()
		if principal, ok := auth.PrincipalFromContext(c.Request.Context()); ok && principal.TokenID != "" {
			key = principal.TokenID
		}
		if !l.allow(key) {
			metrics.IncRateLimited()
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error_code": common.ErrCodeForbidden,
				"message":    "rate limit exceeded",
			})
			return
		}
		c.Next()
	}
}

func (l *RateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.limit - 1, lastRefill: now}
		return true
	}

	elapsed := now.Sub(b.lastRefill)
	if elapsed >= l.interval {
		b.tokens = l.limit
		b.lastRefill = now
	} else {
		refill := (float64(elapsed) / float64(l.interval)) * l.limit
		b.tokens = min(l.limit, b.tokens+refill)
		b.lastRefill = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
