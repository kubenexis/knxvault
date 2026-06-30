package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/app"
)

func TestSealGuardBlocksWrites(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x55
	}
	seal := app.NewSealState(key)
	seal.Seal()

	r := gin.New()
	r.Use(middleware.SealGuard(seal))
	r.POST("/secrets/kv/app", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/health", func(c *gin.Context) { c.Status(http.StatusOK) })
	postReq := httptest.NewRequest(http.MethodPost, "/secrets/kv/app", nil)
	postRec := httptest.NewRecorder()
	r.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST status = %d, want 503", postRec.Code)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	getRec := httptest.NewRecorder()
	r.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", getRec.Code)
	}

	mutateReq := httptest.NewRequest(http.MethodDelete, "/secrets/kv/app", nil)
	mutateRec := httptest.NewRecorder()
	r.ServeHTTP(mutateRec, mutateReq)
	if mutateRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("DELETE status = %d, want 503", mutateRec.Code)
	}
}
