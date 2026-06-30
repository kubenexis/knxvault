package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/infra/metrics"
)

func TestMiddlewareAndHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	metrics.SetBuildInfo("test", "abc123", "1710000000")

	r := gin.New()
	r.Use(metrics.Middleware())
	r.GET("/health", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	r.GET("/metrics", metrics.Handler())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d", rec.Code)
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	r.ServeHTTP(metricsRec, metricsReq)
	if metricsRec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", metricsRec.Code)
	}
	body := metricsRec.Body.String()
	if !strings.Contains(body, "knxvault_http_requests_total") {
		t.Fatalf("metrics body missing request counter: %s", body)
	}
	if !strings.Contains(body, "knxvault_build_info") {
		t.Fatalf("metrics body missing build info: %s", body)
	}
}
