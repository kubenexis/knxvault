package middleware_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/middleware"
)

func TestExposureSigningRejectsReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := "exposure-secret"
	signing := middleware.NewExposureSigning(key)
	body := []byte(`{"detector":"scanner","fingerprint":"fp-1"}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := middleware.SignExposurePayload(key, ts, body)

	r := gin.New()
	r.POST("/sys/exposure/report", signing.Middleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/sys/exposure/report", bytes.NewReader(body))
	req.Header.Set("X-KNXVault-Exposure-Signature", sig)
	req.Header.Set("X-KNXVault-Exposure-Timestamp", ts)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/sys/exposure/report", bytes.NewReader(body))
	req.Header.Set("X-KNXVault-Exposure-Signature", sig)
	req.Header.Set("X-KNXVault-Exposure-Timestamp", ts)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", rec.Code)
	}
}

func TestExposureSigningRejectsStaleTimestamp(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := "exposure-secret"
	signing := middleware.NewExposureSigning(key)
	body := []byte(`{"detector":"scanner"}`)
	ts := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	sig := middleware.SignExposurePayload(key, ts, body)

	r := gin.New()
	r.POST("/sys/exposure/report", signing.Middleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/sys/exposure/report", bytes.NewReader(body))
	req.Header.Set("X-KNXVault-Exposure-Signature", sig)
	req.Header.Set("X-KNXVault-Exposure-Timestamp", ts)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for stale timestamp", rec.Code)
	}
}
