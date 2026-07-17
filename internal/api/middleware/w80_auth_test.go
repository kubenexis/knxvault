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

func TestW80_FineGrainedPKIWithoutCoarseFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	// Policy only has coarse "pki" — insufficient when fallback disabled.
	rbac.UpsertPolicy(domainauth.Policy{
		Name:      "pki-coarse-only",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"pki"},
		Actions:   []string{"write"},
	})
	rbac.UpsertPolicy(domainauth.Policy{
		Name:      "pki-ca-write",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"pki/ca"},
		Actions:   []string{"write"},
	})
	svc := auth.NewService(store, rbac, "")

	coarseTok, _, err := store.Create(context.Background(), "coarse", []string{"pki-coarse-only"}, time.Hour, true, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	fineTok, _, err := store.Create(context.Background(), "fine", []string{"pki-ca-write"}, time.Hour, true, time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.Use(middleware.ErrorHandler(), middleware.Auth(svc))
	// Production path: RequirePermission only (no coarse fallback pair).
	r.POST("/pki/root", middleware.RequirePermission(svc, "pki/ca", "write"), func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})

	req := httptest.NewRequest(http.MethodPost, "/pki/root", nil)
	req.Header.Set("Authorization", "Bearer "+coarseTok)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusCreated {
		t.Fatal("coarse-only policy must not authorize pki/ca when fallback off")
	}
	if rec.Code < 400 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/pki/root", nil)
	req2.Header.Set("Authorization", "Bearer "+fineTok)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("fine-grained status=%d want 201 body=%s", rec2.Code, rec2.Body.String())
	}
}
