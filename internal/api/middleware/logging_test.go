package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/auth"
)

func TestRequestLoggerIncludesRequestIDAndActor(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, recorded := observer.New(zap.InfoLevel)
	log := zap.New(core)

	r := gin.New()
	r.Use(middleware.RequestID())
	r.Use(func(c *gin.Context) {
		ctx := auth.WithPrincipal(c.Request.Context(), auth.Principal{Subject: "alice"})
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	r.Use(middleware.RequestLogger(log))
	r.GET("/health", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-ID", "req-123")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if recorded.Len() != 1 {
		t.Fatalf("log entries = %d, want 1", recorded.Len())
	}
	entry := recorded.All()[0]
	fields := entry.ContextMap()
	if fields["request_id"] != "req-123" {
		t.Fatalf("request_id = %v", fields["request_id"])
	}
	if fields["actor"] != "alice" {
		t.Fatalf("actor = %v", fields["actor"])
	}
}
