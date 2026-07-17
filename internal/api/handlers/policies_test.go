// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestPolicyHandlerCRUD(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rbac := auth.NewRBAC()
	policySvc := service.NewPolicyService(
		memory.NewPolicyRepository(),
		memory.NewRoleRepository(),
		rbac,
		testAuditService(),
	)
	handler := handlers.NewPolicyHandler(policySvc)
	authSvc := testAuthService("policy-admin", "admin")

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.PUT("/sys/policies/:name", middleware.RequirePermission(authSvc, "sys/policies", "write"), handler.PutPolicy)
	r.GET("/sys/policies/:name", middleware.RequirePermission(authSvc, "sys/policies", "read"), handler.GetPolicy)
	r.GET("/sys/policies", middleware.RequirePermission(authSvc, "sys/policies", "read"), handler.ListPolicies)
	r.DELETE("/sys/policies/:name", middleware.RequirePermission(authSvc, "sys/policies", "write"), handler.DeletePolicy)
	r.PUT("/sys/roles/:name", middleware.RequirePermission(authSvc, "sys/policies", "write"), handler.PutRole)
	r.GET("/sys/roles", middleware.RequirePermission(authSvc, "sys/roles", "read"), handler.ListRoles)
	r.GET("/sys/roles/:name", middleware.RequirePermission(authSvc, "sys/roles", "read"), handler.GetRole)
	r.DELETE("/sys/roles/:name", middleware.RequirePermission(authSvc, "sys/policies", "write"), handler.DeleteRole)

	policyBody, _ := json.Marshal(dto.PolicyRequest{
		Effect:    "allow",
		Resources: []string{"secrets/kv/*"},
		Actions:   []string{"read"},
	})
	req := httptest.NewRequest(http.MethodPut, "/sys/policies/office-read", bytes.NewReader(policyBody))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("put policy status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/sys/policies/office-read", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get policy status = %d body = %s", rec.Code, rec.Body.String())
	}
	var policy dto.PolicyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &policy); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if policy.Name != "office-read" {
		t.Fatalf("policy name = %q", policy.Name)
	}

	req = httptest.NewRequest(http.MethodGet, "/sys/policies", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list policies status = %d body = %s", rec.Code, rec.Body.String())
	}

	roleBody, _ := json.Marshal(dto.RoleRequest{
		Policies:                      []string{"office-read"},
		BoundServiceAccountNames:      []string{"my-app"},
		BoundServiceAccountNamespaces: []string{"prod"},
	})
	req = httptest.NewRequest(http.MethodPut, "/sys/roles/app", bytes.NewReader(roleBody))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("put role status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/sys/roles", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list roles status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/sys/roles/app", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get role status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/sys/roles/app", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete role status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/sys/policies/office-read", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete policy status = %d body = %s", rec.Code, rec.Body.String())
	}
}
