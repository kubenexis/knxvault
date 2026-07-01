package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestAuthSetsNamespaceHeader(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := auth.NewTokenStore(time.Hour)
	ctx := t.Context()
	if err := store.RegisterRootToken(ctx, "root", []string{"admin"}); err != nil {
		t.Fatalf("RegisterRootToken() = %v", err)
	}
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name:      "ns-prod",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"secrets/kv/*"},
		Actions:   []string{"read"},
		Conditions: map[string]any{
			"namespace": "prod",
		},
	})
	svc := auth.NewService(store, rbac, "")

	r := gin.New()
	r.Use(middleware.Auth(svc))
	r.GET("/check", func(c *gin.Context) {
		reqCtx, ok := auth.RequestContextFromContext(c.Request.Context())
		if !ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		if !auth.PolicyMatches(domainauth.Policy{
			Name:      "ns-prod",
			Effect:    domainauth.EffectAllow,
			Resources: []string{"secrets/kv/*"},
			Actions:   []string{"read"},
			Conditions: map[string]any{
				"namespace": "prod",
			},
		}, "secrets/kv/app", "read", reqCtx) {
			c.Status(http.StatusForbidden)
			return
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/check", nil)
	req.Header.Set("Authorization", "Bearer root")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 without namespace header", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/check", nil)
	req.Header.Set("Authorization", "Bearer root")
	req.Header.Set("X-KNX-Namespace", "prod")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with namespace header", w.Code)
	}
}