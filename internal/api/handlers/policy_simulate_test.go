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
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestPolicySimulateAllowDenyAndCondition(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name: "team-a", Effect: domainauth.EffectAllow,
		Resources: []string{"secrets/kv/team-a/*"}, Actions: []string{"read"},
	})
	rbac.UpsertPolicy(domainauth.Policy{
		Name: "staging-only", Effect: domainauth.EffectAllow,
		Resources: []string{"secrets/kv/*"}, Actions: []string{"read"},
		Conditions: map[string]any{"environment": "staging"},
	})
	authSvc := auth.NewService(auth.NewTokenStore(time.Hour), rbac, "")

	handler := handlers.NewPolicySimulateHandler(authSvc)
	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.POST("/sys/policy/simulate", handler.Simulate)

	allowBody, _ := json.Marshal(dto.PolicySimulateRequest{
		Policies:   []string{"team-a"},
		Resource:   "secrets/kv/team-a/x",
		Capability: "read",
	})
	req := httptest.NewRequest(http.MethodPost, "/sys/policy/simulate", bytes.NewReader(allowBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("allow status = %d body = %s", rec.Code, rec.Body.String())
	}
	var allowResp dto.PolicySimulateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &allowResp); err != nil {
		t.Fatalf("decode allow: %v", err)
	}
	if !allowResp.Allowed {
		t.Fatalf("expected allow, got %+v", allowResp)
	}

	denyBody, _ := json.Marshal(dto.PolicySimulateRequest{
		Policies:   []string{"team-a"},
		Resource:   "secrets/kv/team-b/x",
		Capability: "read",
	})
	req = httptest.NewRequest(http.MethodPost, "/sys/policy/simulate", bytes.NewReader(denyBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("deny status = %d", rec.Code)
	}
	var denyResp dto.PolicySimulateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &denyResp); err != nil {
		t.Fatalf("decode deny: %v", err)
	}
	if denyResp.Allowed {
		t.Fatal("expected deny for team-b path")
	}

	condBody, _ := json.Marshal(dto.PolicySimulateRequest{
		Policies:    []string{"staging-only"},
		Resource:    "secrets/kv/app/x",
		Capability:  "read",
		Environment: "prod",
	})
	req = httptest.NewRequest(http.MethodPost, "/sys/policy/simulate", bytes.NewReader(condBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("condition status = %d", rec.Code)
	}
	var condResp dto.PolicySimulateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &condResp); err != nil {
		t.Fatalf("decode condition: %v", err)
	}
	if condResp.Allowed {
		t.Fatal("expected environment condition to deny prod")
	}
}