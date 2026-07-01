package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/handlers"
)

func TestVaultCompatLoginKubernetesRequiresAuth(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	compat := handlers.NewVaultCompatHandler(nil, nil)
	r := gin.New()
	r.POST("/v1/auth/kubernetes", compat.LoginKubernetes)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/kubernetes", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestVaultCompatSignRequiresPKI(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	compat := handlers.NewVaultCompatHandler(nil, nil)
	r := gin.New()
	r.POST("/v1/pki/sign/:role", compat.SignCertificate)

	req := httptest.NewRequest(http.MethodPost, "/v1/pki/sign/web", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}