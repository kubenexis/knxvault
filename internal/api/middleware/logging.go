// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package middleware provides HTTP middleware for the API layer.
package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/auth"
)

// RequestLogger logs one line per HTTP request.
func RequestLogger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		fields := []zap.Field{
			zap.String("request_id", requestID(c)),
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("route", c.FullPath()),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
			zap.String("actor", actor(c)),
		}
		log.Info("http request", fields...)
	}
}

func requestID(c *gin.Context) string {
	if v, ok := c.Get("request_id"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func actor(c *gin.Context) string {
	if principal, ok := auth.PrincipalFromContext(c.Request.Context()); ok {
		return principal.Subject
	}
	return "anonymous"
}
