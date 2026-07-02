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
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestSecretsHandlerWriteRead(t *testing.T) {
	gin.SetMode(gin.TestMode)

	key := make([]byte, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	tokenStore := auth.NewTokenStore(time.Hour)
	_ = tokenStore.RegisterRootToken(context.Background(), "root-token", []string{"secrets-admin"})
	authSvc := auth.NewService(tokenStore, auth.NewRBAC(), "")

	auditRepo := memory.NewAuditRepository()
	secretsSvc := service.NewSecretsService(
		secretsengine.NewKVV2Engine(memory.NewSecretRepository(), cryptoSvc),
		auditsvc.NewService(auditRepo),
	)
	handler := handlers.NewSecretsHandler(secretsSvc, nil, nil)

	r := gin.New()
	r.Use(middleware.Auth(authSvc))
	r.POST("/secrets/kv/*path", middleware.RequirePermission(authSvc, "secrets/kv", "write"), handler.Write)
	r.GET("/secrets/kv/*path", middleware.RequirePermission(authSvc, "secrets/kv", "read"), handler.Read)

	body, _ := json.Marshal(dto.KVWriteRequest{Data: map[string]any{"user": "alice"}})
	req := httptest.NewRequest(http.MethodPost, "/secrets/kv/app/config", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("write status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/secrets/kv/app/config", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("read status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestSecretsHandlerListMetadataDestroy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	key := make([]byte, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}

	tokenStore := auth.NewTokenStore(time.Hour)
	_ = tokenStore.RegisterRootToken(context.Background(), "root-token", []string{"secrets-admin"})
	authSvc := auth.NewService(tokenStore, auth.NewRBAC(), "")

	auditRepo := memory.NewAuditRepository()
	secretsSvc := service.NewSecretsService(
		secretsengine.NewKVV2Engine(memory.NewSecretRepository(), cryptoSvc),
		auditsvc.NewService(auditRepo),
	)
	handler := handlers.NewSecretsHandler(secretsSvc, nil, nil)

	r := gin.New()
	r.Use(middleware.Auth(authSvc))
	r.POST("/secrets/kv/*path", middleware.RequirePermission(authSvc, "secrets/kv", "write"), handler.Write)
	r.GET("/secrets/kv/*path", middleware.RequirePermission(authSvc, "secrets/kv", "read"), handler.Read)
	r.DELETE("/secrets/kv/*path", middleware.RequirePermission(authSvc, "secrets/kv", "write"), handler.Delete)

	body, _ := json.Marshal(dto.KVWriteRequest{Data: map[string]any{"v": "1"}})
	req := httptest.NewRequest(http.MethodPost, "/secrets/kv/app/a", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("write status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/secrets/kv/?list=true&prefix=app/", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/secrets/kv/app/a/metadata", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/secrets/kv/app/a?version=1", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("destroy status = %d", rec.Code)
	}
}

func TestSecretsHandlerRejectsPathTraversal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := make([]byte, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	tokenStore := auth.NewTokenStore(time.Hour)
	_ = tokenStore.RegisterRootToken(context.Background(), "root-token", []string{"secrets-admin"})
	authSvc := auth.NewService(tokenStore, auth.NewRBAC(), "")
	secretsSvc := service.NewSecretsService(
		secretsengine.NewKVV2Engine(memory.NewSecretRepository(), cryptoSvc),
		auditsvc.NewService(memory.NewAuditRepository()),
	)
	handler := handlers.NewSecretsHandler(secretsSvc, nil, nil)
	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.Use(middleware.Auth(authSvc))
	r.GET("/secrets/kv/*path", middleware.RequirePermission(authSvc, "secrets/kv", "read"), handler.Read)

	req := httptest.NewRequest(http.MethodGet, "/secrets/kv/public/../admin/secret", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for .. path, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSecretsHandlerReadInvalidVersionQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := make([]byte, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	tokenStore := auth.NewTokenStore(time.Hour)
	_ = tokenStore.RegisterRootToken(context.Background(), "root-token", []string{"secrets-admin"})
	authSvc := auth.NewService(tokenStore, auth.NewRBAC(), "")
	secretsSvc := service.NewSecretsService(
		secretsengine.NewKVV2Engine(memory.NewSecretRepository(), cryptoSvc),
		auditsvc.NewService(memory.NewAuditRepository()),
	)
	handler := handlers.NewSecretsHandler(secretsSvc, nil, nil)
	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.Use(middleware.Auth(authSvc))
	r.GET("/secrets/kv/*path", middleware.RequirePermission(authSvc, "secrets/kv", "read"), handler.Read)

	req := httptest.NewRequest(http.MethodGet, "/secrets/kv/app/a?version=abc", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid version, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSecretsHandlerDeleteInvalidVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := make([]byte, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	tokenStore := auth.NewTokenStore(time.Hour)
	_ = tokenStore.RegisterRootToken(context.Background(), "root-token", []string{"secrets-admin"})
	authSvc := auth.NewService(tokenStore, auth.NewRBAC(), "")
	secretsSvc := service.NewSecretsService(
		secretsengine.NewKVV2Engine(memory.NewSecretRepository(), cryptoSvc),
		auditsvc.NewService(memory.NewAuditRepository()),
	)
	handler := handlers.NewSecretsHandler(secretsSvc, nil, nil)
	r := gin.New()
	r.Use(middleware.ErrorHandler())
	r.Use(middleware.Auth(authSvc))
	r.DELETE("/secrets/kv/*path", middleware.RequirePermission(authSvc, "secrets/kv", "write"), handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/secrets/kv/app/a?version=0", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for version=0, got %d body=%s", rec.Code, rec.Body.String())
	}
}
