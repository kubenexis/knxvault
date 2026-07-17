// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api"
)

func TestRegisterOpenAPIRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	api.RegisterOpenAPIRoutes(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "openapi:") {
		t.Fatal("expected openapi document body")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "yaml") {
		t.Fatalf("content-type = %q", ct)
	}

	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/swagger", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("swagger status = %d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "swagger-ui") {
		t.Fatal("expected swagger UI html")
	}
}
