// Copyright Kubenexis Systems Private Limited.
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
	sshengine "github.com/kubenexis/knxvault/internal/engine/secrets/ssh"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestSSHHandlerRoleAndCredsRequiresCA(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cryptoSvc, err := testCryptoService()
	if err != nil {
		t.Fatalf("testCryptoService() = %v", err)
	}
	engine := sshengine.NewEngine(
		memory.NewSSHRoleRepository(),
		memory.NewLeaseRepository(),
		memory.NewSecretRepository(),
		cryptoSvc,
	)
	svc := service.NewSSHService(engine, testAuditService())
	handler := handlers.NewSSHHandler(svc)
	authSvc := testAuthService("secrets-admin")

	r := gin.New()
	r.Use(middleware.Auth(authSvc), middleware.ErrorHandler())
	r.PUT("/secrets/ssh/roles/:name", handler.PutRole)
	r.POST("/secrets/ssh/creds/:role", handler.GenerateCreds)

	roleBody, _ := json.Marshal(dto.SSHRoleRequest{
		TTLSeconds:  600,
		CAKeyPath:   "ssh/ca/root",
		DefaultUser: "deploy",
	})
	putReq := httptest.NewRequest(http.MethodPut, "/secrets/ssh/roles/ops", bytes.NewReader(roleBody))
	putReq.Header.Set("Authorization", "Bearer root-token")
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	r.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusNoContent {
		t.Fatalf("put role status = %d body = %s", putRec.Code, putRec.Body.String())
	}

	credsReq := httptest.NewRequest(http.MethodPost, "/secrets/ssh/creds/ops", nil)
	credsReq.Header.Set("Authorization", "Bearer root-token")
	credsRec := httptest.NewRecorder()
	r.ServeHTTP(credsRec, credsReq)
	if credsRec.Code == http.StatusOK {
		t.Fatal("expected error without ca key in kv")
	}
}
