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
)

func TestW79_RequireAnyPermissionFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := auth.NewTokenStore(time.Hour)
	// Built-in admin policy grants "*" which covers pki/ca and coarse pki.
	svc := auth.NewService(store, auth.NewRBAC(), "")
	tok, _, err := store.Create(context.Background(), "u", []string{"admin"}, time.Hour, false, time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.Use(middleware.Auth(svc))
	r.POST("/pki/root", middleware.RequireAnyPermission(svc, "pki/ca", "write", "pki", "write"), func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})
	req := httptest.NewRequest(http.MethodPost, "/pki/root", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d", rec.Code)
	}
}
