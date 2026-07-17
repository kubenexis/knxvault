// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/app"
)

func TestSealGuardBlocksReadsAndWrites(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x55
	}
	seal := app.NewSealState(key) // starts sealed

	r := gin.New()
	r.Use(middleware.SealGuard(seal))
	r.POST("/secrets/kv/app", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/secrets/kv/app", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.DELETE("/secrets/kv/app", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		req := httptest.NewRequest(method, "/secrets/kv/app", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status = %d, want 503", method, rec.Code)
		}
	}

	if !seal.Unseal(key) {
		t.Fatal("unseal")
	}
	req := httptest.NewRequest(http.MethodGet, "/secrets/kv/app", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET after unseal = %d", rec.Code)
	}
}

func TestSealGuardRejectsSuffixBypass(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := make([]byte, 32)
	seal := app.NewSealState(key) // sealed
	r := gin.New()
	r.Use(middleware.SealGuard(seal))
	r.POST("/evil/sys/unseal", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.POST("/sys/unseal", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodPost, "/evil/sys/unseal", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("suffix bypass status = %d, want 503", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/sys/unseal", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("exact unseal status = %d", rec.Code)
	}
}
