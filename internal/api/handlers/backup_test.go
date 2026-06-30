package handlers_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/api/handlers"
	"github.com/kubenexis/knxvault/internal/api/middleware"
	"github.com/kubenexis/knxvault/internal/backup"
	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestBackupHandlerCreateRestore(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cryptoSvc, err := testCryptoService()
	if err != nil {
		t.Fatalf("testCryptoService() = %v", err)
	}
	sourceRepos := backup.Repos{
		CA:     memory.NewCARepository(),
		Secret: memory.NewSecretRepository(),
		Revoke: memory.NewRevocationRepository(),
		Lease:  memory.NewLeaseRepository(),
		Policy: memory.NewPolicyRepository(),
		Role:   memory.NewRoleRepository(),
	}
	targetRepos := backup.Repos{
		CA:     memory.NewCARepository(),
		Secret: memory.NewSecretRepository(),
		Revoke: memory.NewRevocationRepository(),
		Lease:  memory.NewLeaseRepository(),
		Policy: memory.NewPolicyRepository(),
		Role:   memory.NewRoleRepository(),
	}
	createSvc := service.NewBackupService(sourceRepos, cryptoSvc, testAuditService())
	restoreSvc := service.NewBackupService(targetRepos, cryptoSvc, testAuditService())
	handler := handlers.NewBackupHandler(createSvc)
	restoreHandler := handlers.NewBackupHandler(restoreSvc)
	authSvc := testAuthService("admin")

	ctx := t.Context()
	caID := uuid.New()
	now := time.Now().UTC()
	if err := sourceRepos.CA.Save(ctx, &domainpki.CA{
		ID:            caID,
		Name:          "root",
		Type:          domainpki.CATypeRoot,
		Subject:       domainpki.DistinguishedName{CommonName: "Root"},
		Serial:        "01",
		CertPEM:       "pem",
		PrivateKeyEnc: []byte("key"),
		DEKEnc:        []byte("dek"),
		Status:        domainpki.CAStatusActive,
		CreatedAt:     now,
		ExpiresAt:     now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	secretID := uuid.New()
	if err := sourceRepos.Secret.SaveVersion(ctx, &secrets.SecretVersion{
		ID:        secretID,
		Path:      "app/db",
		Version:   1,
		DataEnc:   []byte("data"),
		DEKEnc:    []byte("dek"),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("SaveVersion() = %v", err)
	}

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.POST("/sys/backup", middleware.RequirePermission(authSvc, "sys/backup", "write"), handler.Create)
	r.POST("/sys/restore", middleware.RequirePermission(authSvc, "sys/backup", "write"), restoreHandler.Restore)

	createBody, _ := json.Marshal(dto.BackupCreateRequest{})
	req := httptest.NewRequest(http.MethodPost, "/sys/backup", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d body = %s", rec.Code, rec.Body.String())
	}
	var created dto.BackupCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	archive, err := base64.StdEncoding.DecodeString(created.Data)
	if err != nil {
		t.Fatalf("decode archive: %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/sys/restore", bytes.NewReader(archive))
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("restore status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestBackupHandlerRestoreRequiresPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cryptoSvc, err := testCryptoService()
	if err != nil {
		t.Fatalf("testCryptoService() = %v", err)
	}
	handler := handlers.NewBackupHandler(service.NewBackupService(backup.Repos{
		CA:     memory.NewCARepository(),
		Secret: memory.NewSecretRepository(),
	}, cryptoSvc, testAuditService()))
	authSvc := testAuthService("admin")

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.POST("/sys/restore", middleware.RequirePermission(authSvc, "sys/backup", "write"), handler.Restore)

	req := httptest.NewRequest(http.MethodPost, "/sys/restore", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer root-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}
