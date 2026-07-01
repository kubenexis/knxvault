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
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestDatabaseHandlerRoleAndCreds(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cryptoSvc, err := testCryptoService()
	if err != nil {
		t.Fatalf("testCryptoService() = %v", err)
	}
	engine := databaseengine.NewEngine(
		memory.NewDatabaseRoleRepository(),
		memory.NewLeaseRepository(),
		memory.NewSecretRepository(),
		cryptoSvc,
	)
	dbSvc := service.NewDatabaseService(engine, testAuditService())
	handler := handlers.NewDatabaseHandler(dbSvc)
	authSvc := testAuthService("secrets-admin")

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.PUT("/secrets/database/roles/:name", middleware.RequirePermission(authSvc, "secrets/database", "write"), handler.PutRole)
	r.GET("/secrets/database/roles/:name", middleware.RequirePermission(authSvc, "secrets/database", "read"), handler.GetRole)
	r.POST("/secrets/database/creds/:role", middleware.RequirePermission(authSvc, "secrets/database", "write"), handler.GenerateCreds)
	r.POST("/secrets/database/renew/:lease_id", middleware.RequirePermission(authSvc, "secrets/database", "write"), handler.Renew)
	r.PUT("/secrets/database/revoke/:lease_id", middleware.RequirePermission(authSvc, "secrets/database", "write"), handler.Revoke)

	roleBody, _ := json.Marshal(dto.DatabaseRoleRequest{
		TTLSeconds: 60,
		CreationStatements: []string{
			"CREATE USER {{username}} PASSWORD '{{password}}';",
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/secrets/database/roles/readonly", bytes.NewReader(roleBody))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("put role status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/secrets/database/roles/readonly", nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get role status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/secrets/database/creds/readonly", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate creds status = %d body = %s", rec.Code, rec.Body.String())
	}
	var creds dto.DatabaseCredsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &creds); err != nil {
		t.Fatalf("decode creds: %v", err)
	}
	if creds.LeaseID == "" {
		t.Fatal("expected lease id")
	}

	renewBody, _ := json.Marshal(dto.DatabaseRenewRequest{TTLSeconds: 120})
	req = httptest.NewRequest(http.MethodPost, "/secrets/database/renew/"+creds.LeaseID, bytes.NewReader(renewBody))
	req.Header.Set("Authorization", "Bearer root-token")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPut, "/secrets/database/revoke/"+creds.LeaseID, nil)
	req.Header.Set("Authorization", "Bearer root-token")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body = %s", rec.Code, rec.Body.String())
	}
}
