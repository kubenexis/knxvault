// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/kubenexis/knxvault/internal/cache"
)

func TestW80_ExposureReplayViaSharedCache(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := "exposure-secret"
	store := cache.NewMemoryStore()
	signing := middleware.NewExposureSigning(key)
	signing.SetReplayStore(middleware.NewCacheExposureReplayStore(store))

	body := []byte(`{"detector":"scanner","fingerprint":"fp-ha"}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := middleware.SignExposurePayload(key, ts, body)

	r := gin.New()
	r.POST("/sys/exposure/report", signing.Middleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Two independent middleware instances share the same cache (HA simulation).
	signing2 := middleware.NewExposureSigning(key)
	signing2.SetReplayStore(middleware.NewCacheExposureReplayStore(store))
	r2 := gin.New()
	r2.POST("/sys/exposure/report", signing2.Middleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/sys/exposure/report", bytes.NewReader(body))
	req.Header.Set("X-KNXVault-Exposure-Signature", sig)
	req.Header.Set("X-KNXVault-Exposure-Timestamp", ts)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/sys/exposure/report", bytes.NewReader(body))
	req2.Header.Set("X-KNXVault-Exposure-Signature", sig)
	req2.Header.Set("X-KNXVault-Exposure-Timestamp", ts)
	rec2 := httptest.NewRecorder()
	r2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("cross-instance replay status=%d want 401", rec2.Code)
	}
}
