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

func TestRequirePathCapabilityFailClosedNilService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.GET("/secrets/kv/*path", middleware.RequirePathCapability(nil, "secrets/kv", auth.CapRead, "path", nil), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/secrets/kv/app", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("nil auth service must fail closed")
	}
}

func TestRequirePKISignCapabilityPathScoped(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	// Path-scoped policy (W52-04: coarse "pki" write alone is insufficient).
	rbac.UpsertPolicy(domainauth.Policy{
		Name:      "pki-sign",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"pki/sign/*", "pki/*"},
		Actions:   []string{"write"},
	})
	rbac.UpsertPolicy(domainauth.Policy{
		Name:      "pki-coarse",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"pki"},
		Actions:   []string{"write"},
	})
	token, _, err := store.Create(context.Background(), "issuer", []string{"pki-sign"}, time.Hour, true, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	coarse, _, err := store.Create(context.Background(), "coarse", []string{"pki-coarse"}, time.Hour, true, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(store, rbac, "")
	r := gin.New()
	r.Use(middleware.ErrorHandler(), middleware.Auth(svc))
	r.POST("/v1/pki/sign/:role", middleware.RequirePKISignCapability(svc, "pki"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/pki/sign/web", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("path-scoped status = %d body=%s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/pki/sign/web", nil)
	req.Header.Set("Authorization", "Bearer "+coarse)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("coarse pki write must not authorize sign")
	}
}

func TestRequireKVAccessFailClosedNilService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.GET("/secrets/kv/*path", middleware.RequireKVAccess(nil, auth.CapRead, nil), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/secrets/kv/app", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("nil auth must fail closed for KV access")
	}
}

func TestAuthAcceptsVaultTokenHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name: "admin", Effect: domainauth.EffectAllow,
		Resources: []string{"*"}, Actions: []string{"*"},
	})
	token, _, err := store.Create(context.Background(), "root", []string{"admin"}, time.Hour, true, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(store, rbac, "")
	r := gin.New()
	r.Use(middleware.ErrorHandler(), middleware.Auth(svc))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Vault-Token", token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}
