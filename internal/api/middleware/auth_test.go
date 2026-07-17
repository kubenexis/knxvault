// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestAuthMiddlewareNamespaceRBAC(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name:      "prod-read",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"secrets/kv/*"},
		Actions:   []string{"read"},
		Conditions: map[string]any{
			"namespace": "prod",
		},
	})
	token := issueTestToken(t, store, "system:serviceaccount:dev:app", []string{"prod-read"})

	svc := auth.NewService(store, rbac, "")
	r := gin.New()
	r.Use(middleware.Auth(svc), middleware.ErrorHandler())
	r.GET("/secrets", middleware.RequirePermission(svc, "secrets/kv/app", "read"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("without namespace status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(auth.NamespaceHeader, "prod")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("with namespace status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddlewareNamespaceFromSubject(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name:      "prod-read",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"secrets/kv/*"},
		Actions:   []string{"read"},
		Conditions: map[string]any{
			"namespace": "prod",
		},
	})
	token := issueTestToken(t, store, "system:serviceaccount:prod:app", []string{"prod-read"})
	svc := auth.NewService(store, rbac, "")

	r := gin.New()
	r.Use(middleware.Auth(svc), middleware.ErrorHandler())
	r.GET("/secrets", middleware.RequirePermission(svc, "secrets/kv/app", "read"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func issueTestToken(t *testing.T, store *auth.TokenStore, subject string, policies []string) string {
	t.Helper()
	token, _, err := store.Create(context.Background(), subject, policies, time.Hour, true, time.Time{})
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	return token
}
