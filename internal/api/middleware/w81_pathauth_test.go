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

func TestW81_PKISignDoesNotBleedAcrossMounts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name:      "pki-sign-web",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"pki/sign/web", "pki/sign/*"},
		Actions:   []string{"write"},
	})
	svc := auth.NewService(store, rbac, "")
	tok, _, err := store.Create(context.Background(), "u", []string{"pki-sign-web"}, time.Hour, true, time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.Use(middleware.ErrorHandler(), middleware.Auth(svc))
	r.POST("/v1/:mount/sign/:role", middleware.RequirePKISignCapability(svc, ""), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Same mount pki should work.
	req := httptest.NewRequest(http.MethodPost, "/v1/pki/sign/web", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pki mount status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Custom mount must not succeed via pki/* bleed.
	req2 := httptest.NewRequest(http.MethodPost, "/v1/pki_int/sign/web", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusOK {
		t.Fatal("expected deny for pki_int when policy is only pki/sign/*")
	}
}
