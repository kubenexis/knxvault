package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/infra/k8s"
)

func TestAuthHandlerKubernetesFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authSvc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	authSvc.SetK8sLoginOptions(auth.K8sLoginOptions{RaftEnabled: true})
	handler := handlers.NewAuthHandler(authSvc, time.Hour)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.POST("/auth/kubernetes", handler.LoginKubernetes)

	body, _ := json.Marshal(dto.K8sLoginRequest{Role: "app", JWT: "forged"})
	req := httptest.NewRequest(http.MethodPost, "/auth/kubernetes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandlerCreateRenewRevokeToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tokenStore := auth.NewTokenStore(time.Hour)
	tokenStore.RegisterRootToken("root-token", []string{"admin"})
	authSvc := auth.NewService(tokenStore, auth.NewRBAC(), "")
	handler := handlers.NewAuthHandler(authSvc, time.Hour)

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.POST("/auth/token/create", middleware.RequirePermission(authSvc, "sys", "sudo"), handler.CreateToken)
	r.POST("/auth/token/renew", handler.RenewToken)
	r.DELETE("/auth/token/self", handler.RevokeSelfToken)

	createBody, _ := json.Marshal(dto.TokenCreateRequest{
		Subject:  "ci-bot",
		Policies: []string{"secrets-admin"},
		TTL:      "30m",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/token/create", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d body = %s", rec.Code, rec.Body.String())
	}
	var created dto.LoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ClientToken == "" {
		t.Fatal("expected client token")
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/token/renew", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+created.ClientToken)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/auth/token/self", nil)
	req.Header.Set("Authorization", "Bearer "+created.ClientToken)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandlerKubernetesTokenReview(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reviewer := &k8s.FakeTokenReviewer{
		Result: &k8s.TokenReviewResult{
			Authenticated:      true,
			Username:           "system:serviceaccount:prod:my-app",
			Namespace:          "prod",
			ServiceAccountName: "my-app",
		},
	}
	authSvc := auth.NewService(auth.NewTokenStore(time.Hour), auth.NewRBAC(), "")
	authSvc.SetK8sLoginOptions(auth.K8sLoginOptions{TokenReviewer: reviewer})
	handler := handlers.NewAuthHandler(authSvc, time.Hour)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.POST("/auth/kubernetes", handler.LoginKubernetes)

	body, _ := json.Marshal(dto.K8sLoginRequest{Role: "admin", JWT: "real-sa-jwt"})
	req := httptest.NewRequest(http.MethodPost, "/auth/kubernetes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if reviewer.Last != "real-sa-jwt" {
		t.Fatalf("TokenReview last = %q", reviewer.Last)
	}
}