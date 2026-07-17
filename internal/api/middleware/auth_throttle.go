// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
)

// AuthLoginThrottle wraps a rate limiter with auth-specific metrics (W43-03).
func AuthLoginThrottle(l *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if l == nil {
			c.Next()
			return
		}
		inner := l.Middleware()
		inner(c)
		if c.IsAborted() && c.Writer.Status() == http.StatusTooManyRequests {
			metrics.IncAuthLoginThrottled()
		}
	}
}

// TokenCreateThrottle wraps token create rate limiting (W43-05).
func TokenCreateThrottle(l *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if l == nil {
			c.Next()
			return
		}
		inner := l.Middleware()
		inner(c)
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

// EnvironmentHeader sets request environment from X-KNX-Environment (W44-02).
func EnvironmentHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		env := strings.TrimSpace(c.GetHeader("X-KNX-Environment"))
		if env != "" {
			c.Set("knx_environment", env)
		}
		c.Next()
	}
}
