// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/api/handlers"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestHealthHandlerLive(t *testing.T) {
	h := handlers.NewHealthHandler("1.2.3", nil, nil, nil)
	r := gin.New()
	r.GET("/health", h.Live)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body dto.HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "healthy" {
		t.Errorf("status = %q, want healthy", body.Status)
	}
	if body.Version != "1.2.3" {
		t.Errorf("version = %q, want 1.2.3", body.Version)
	}
}
