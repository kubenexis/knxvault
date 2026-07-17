// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/sys"
)

func TestSysHandlerCapabilities(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authSvc := testAuthService("admin")
	handler := handlers.NewSysHandler(authSvc, nil, nil, nil, nil, nil, nil, nil, testCryptoKey(), false, nil)

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.GET("/sys/capabilities", handler.Capabilities)

	req := httptest.NewRequest(http.MethodGet, "/sys/capabilities", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var resp dto.CapabilitiesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Capabilities) == 0 {
		t.Fatal("expected capabilities for admin")
	}
}

func TestSysHandlerCapabilitiesUnauthenticated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := handlers.NewSysHandler(testAuthService("admin"), nil, nil, nil, nil, nil, nil, nil, nil, false, nil)
	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.GET("/sys/capabilities", handler.Capabilities)

	req := httptest.NewRequest(http.MethodGet, "/sys/capabilities", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp dto.CapabilitiesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Capabilities) != 0 {
		t.Fatalf("capabilities = %v, want empty", resp.Capabilities)
	}
}

func TestSysHandlerIssueListenerTLSRequiresPKI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authSvc := testAuthService("admin")
	handler := handlers.NewSysHandler(authSvc, nil, nil, nil, nil, nil, nil, nil, nil, false, nil)
	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.POST("/sys/tls/issue-listener", middleware.RequirePermission(authSvc, "sys/tls", "write"), handler.IssueListenerTLS)

	req := httptest.NewRequest(http.MethodPost, "/sys/tls/issue-listener", bytes.NewReader([]byte(`{"role":"listener","common_name":"vault.local"}`)))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestSysHandlerInit(t *testing.T) {
	if sys.Initialized() {
		t.Skip("bootstrap state already set in this process")
	}
	gin.SetMode(gin.TestMode)

	authSvc := testAuthService("admin")
	handler := handlers.NewSysHandler(authSvc, nil, nil, nil, nil, nil, nil, nil, testCryptoKey(), false, nil)
	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.POST("/sys/init", middleware.RequirePermission(authSvc, "sys/init", "write"), handler.Init)

	body, _ := json.Marshal(dto.InitRequest{CreateRootCA: false})
	req := httptest.NewRequest(http.MethodPost, "/sys/init", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["initialized"] != true {
		t.Fatalf("initialized = %v", resp["initialized"])
	}
}
