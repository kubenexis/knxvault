package middleware_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/middleware"
)

func TestExposureSigningRejectsReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := []byte("exposure-secret")
	signing := middleware.NewExposureSigning(string(key))
	body := []byte(`{"detector":"scanner","fingerprint":"fp-1"}`)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	r := gin.New()
	r.POST("/sys/exposure/report", signing.Middleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/sys/exposure/report", bytes.NewReader(body))
	req.Header.Set("X-KNXVault-Exposure-Signature", sig)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/sys/exposure/report", bytes.NewReader(body))
	req.Header.Set("X-KNXVault-Exposure-Signature", sig)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", rec.Code)
	}
}
