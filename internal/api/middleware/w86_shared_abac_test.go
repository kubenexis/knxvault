// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/cache"
)

func TestSharedRateLimiterUsesStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := cache.NewMemoryStore()
	lim := middleware.NewSharedRateLimiterPrefixed(2, true, store, "test:unseal:")
	r := gin.New()
	r.POST("/u", lim.Middleware(), func(c *gin.Context) { c.Status(http.StatusOK) })

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/u", nil)
		req.RemoteAddr = "10.1.2.3:9"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if i < 2 && rec.Code != http.StatusOK {
			t.Fatalf("req %d status=%d", i, rec.Code)
		}
		if i == 2 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("req 3 want 429 got %d", rec.Code)
		}
	}
}

func TestABACHeadersIgnoredWhenUntrusted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.EnvironmentHeaderWithConfig(middleware.ABACHeaderConfig{
		TrustClient:       false,
		ServerEnvironment: "prod",
		ServerCluster:     "core-1",
	}))
	r.GET("/x", func(c *gin.Context) {
		env, _ := c.Get("knx_environment")
		cluster, _ := c.Get("knx_cluster")
		c.JSON(http.StatusOK, gin.H{"env": env, "cluster": cluster})
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-KNX-Environment", "attacker-staging")
	req.Header.Set("X-KNX-Cluster", "evil")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if !containsAll(body, "prod", "core-1") || containsAll(body, "attacker") {
		t.Fatalf("body=%s want server ABAC attrs not client headers", body)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if p != "" && !stringContains(s, p) {
			return false
		}
	}
	return true
}

func stringContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()))
}
