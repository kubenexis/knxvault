// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
)

// AuthLoginThrottle wraps a shared (Valkey when configured) rate limiter with auth metrics (W43-03 / W86-10).
// Accepts *SharedRateLimiter or falls back via SharedRateLimiter.Local-compatible *RateLimiter through Shared wrapper.
func AuthLoginThrottle(l *SharedRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if l == nil {
			c.Next()
			return
		}
		l.Middleware()(c)
		if c.IsAborted() && c.Writer.Status() == http.StatusTooManyRequests {
			metrics.IncAuthLoginThrottled()
		}
	}
}

// AuthLoginThrottleLocal is for tests that only construct a process-local limiter.
func AuthLoginThrottleLocal(l *RateLimiter) gin.HandlerFunc {
	if l == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return AuthLoginThrottle(&SharedRateLimiter{local: l, enabled: true, prefix: "test:login:"})
}

// TokenCreateThrottle wraps token create rate limiting (W43-05 / W86-10).
func TokenCreateThrottle(l *SharedRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if l == nil {
			c.Next()
			return
		}
		l.Middleware()(c)
		if c.IsAborted() && c.Writer.Status() == http.StatusTooManyRequests {
			metrics.IncTokenCreateThrottled()
		}
	}
}

// ClientCertRequired optionally enforces mTLS on secured routes (W34-01).
func ClientCertRequired(enabled bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !enabled {
			c.Next()
			return
		}
		if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error_code": common.ErrCodeUnauthorized,
				"message":    "client certificate required",
			})
			return
		}
		c.Next()
	}
}

// ABACHeaderConfig controls whether client-asserted environment/cluster headers are trusted (W86-12).
type ABACHeaderConfig struct {
	// TrustClient when true accepts X-KNX-Environment / X-KNX-Cluster from the client (lab).
	// Production sets TrustClient=false so policies cannot be spoofed via headers alone.
	TrustClient bool
	// ServerEnvironment / ServerCluster are authoritative values when TrustClient is false
	// (injected by the platform, not the caller).
	ServerEnvironment string
	ServerCluster     string
}

// EnvironmentHeader sets request environment/cluster for ABAC (W44-02 / W86-12).
func EnvironmentHeader() gin.HandlerFunc {
	return EnvironmentHeaderWithConfig(ABACHeaderConfig{TrustClient: true})
}

// EnvironmentHeaderWithConfig applies ABAC header policy.
func EnvironmentHeaderWithConfig(cfg ABACHeaderConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		env, cluster := "", ""
		if cfg.TrustClient {
			env = strings.TrimSpace(c.GetHeader("X-KNX-Environment"))
			cluster = strings.TrimSpace(c.GetHeader(auth.ClusterHeader))
		} else {
			env = strings.TrimSpace(cfg.ServerEnvironment)
			cluster = strings.TrimSpace(cfg.ServerCluster)
		}
		if env != "" {
			c.Set("knx_environment", env)
		}
		if cluster != "" {
			c.Set("knx_cluster", cluster)
		}
		c.Next()
	}
}
