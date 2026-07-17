// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/api"
	"github.com/kubenexis/knxvault/internal/auth"
	"go.uber.org/zap"
)

func TestRouterOmitsOIDCAndLDAPWhenDisabled(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	svc := auth.NewService(store, rbac, "")

	r := api.NewRouter(zap.NewNop(), "test", false, api.RouterDeps{
		AuthService:     svc,
		TokenTTL:        time.Hour,
		AuthOIDCEnabled: false,
		AuthLDAPEnabled: false,
	})

	for _, path := range []string{"/auth/oidc/role1", "/auth/ldap"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: status=%d want 404 (route absent)", path, w.Code)
		}
	}

	// Base auth still present (may be 400/401 without body, not 404).
	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusNotFound {
		t.Fatal("/auth/token should be registered")
	}
}

func TestRouterRegistersOIDCAndLDAPWhenEnabled(t *testing.T) {
	store := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	svc := auth.NewService(store, rbac, "")

	r := api.NewRouter(zap.NewNop(), "test", false, api.RouterDeps{
		AuthService:     svc,
		TokenTTL:        time.Hour,
		AuthOIDCEnabled: true,
		AuthLDAPEnabled: true,
	})

	for _, path := range []string{"/auth/oidc/role1", "/auth/ldap"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusNotFound {
			t.Fatalf("%s: got 404, route should exist", path)
		}
	}
}
