package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
)

func TestVaultCompatKubernetesLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := testAuthService("admin")
	handler := handlers.NewVaultCompatHandler(authSvc, nil, time.Hour)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.POST("/v1/auth/kubernetes/login", handler.LoginKubernetes)

	body, _ := json.Marshal(map[string]string{
		"role": "app",
		"jwt":  "forged",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/kubernetes/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestVaultCompatSignPKIRequiresAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := testAuthService("admin")
	handler := handlers.NewVaultCompatHandler(authSvc, nil, time.Hour)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.Use(middleware.Auth(authSvc))
	r.POST("/v1/pki/sign/:role", handler.SignPKI)

	req := httptest.NewRequest(http.MethodPost, "/v1/pki/sign/web-server", bytes.NewReader([]byte(`{"common_name":"test.local"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}
