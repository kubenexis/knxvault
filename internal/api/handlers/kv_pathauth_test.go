package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/crypto"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestKVPathAwareAuthorization(t *testing.T) {
	gin.SetMode(gin.TestMode)

	key := make([]byte, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	tokenStore := auth.NewTokenStore(time.Hour)
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name: "team-a-kv", Effect: domainauth.EffectAllow,
		Resources: []string{"secrets/kv/team-a/*"}, Actions: []string{"read", "write", "list"},
	})
	_ = tokenStore.RegisterRootToken(context.Background(), "team-a-token", []string{"team-a-kv"})
	authSvc := auth.NewService(tokenStore, rbac, "")

	secretsSvc := service.NewSecretsService(
		secretsengine.NewKVV2Engine(memory.NewSecretRepository(), cryptoSvc),
		auditsvc.NewService(memory.NewAuditRepository()),
	)
	handler := handlers.NewSecretsHandler(secretsSvc, nil, authSvc)

	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.Use(middleware.Auth(authSvc))
	readChain := []gin.HandlerFunc{
		middleware.EnrichKVResourceLabels(secretsSvc),
		middleware.RequireKVAccess(authSvc, auth.CapRead, nil),
		handler.Read,
	}
	writeChain := []gin.HandlerFunc{
		middleware.EnrichKVResourceLabels(secretsSvc),
		middleware.RequireKVAccess(authSvc, auth.CapWrite, nil),
		handler.Write,
	}
	r.GET("/secrets/kv/*path", readChain...)
	r.POST("/secrets/kv/*path", writeChain...)

	body, _ := json.Marshal(dto.KVWriteRequest{Data: map[string]any{"v": "1"}})
	req := httptest.NewRequest(http.MethodPost, "/secrets/kv/team-a/secret", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer team-a-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("write team-a status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/secrets/kv/team-a/secret", nil)
	req.Header.Set("Authorization", "Bearer team-a-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("read team-a status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/secrets/kv/team-b/secret", nil)
	req.Header.Set("Authorization", "Bearer team-a-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("read team-b status = %d, want 403 body = %s", rec.Code, rec.Body.String())
	}
}
