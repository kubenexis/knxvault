package middleware_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/middleware"
)

func TestRequestSigningValid(t *testing.T) {
	key := []byte("signing-key")
	signer := middleware.NewRequestSigning(string(key), true)
	r := gin.New()
	r.Use(signer.Middleware())
	r.POST("/secure", func(c *gin.Context) { c.Status(http.StatusOK) })

	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "/secure", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := middleware.SignRequest(req, key); err != nil {
		t.Fatalf("SignRequest() = %v", err)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRequestSigningRejectsTamper(t *testing.T) {
	key := []byte("signing-key")
	signer := middleware.NewRequestSigning(string(key), true)
	r := gin.New()
	r.Use(signer.Middleware())
	r.POST("/secure", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodPost, "/secure", bytes.NewReader([]byte("bad")))
	req.Header.Set("X-KNXVault-Timestamp", "1")
	req.Header.Set("X-KNXVault-Signature", "deadbeef")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
