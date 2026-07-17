// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api"
	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/config"
)

func testMasterKey() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func testUnsealKey() string {
	// Distinct from testMasterKey(); matches internal/config tests.
	return "dGVzdC11bnNlYWwta2V5MTIzNDU2Nzg5MDEyMzQ1Ng=="
}

func newTestRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()

	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	t.Setenv("KNXVAULT_MASTER_KEY", testMasterKey())
	t.Setenv("KNXVAULT_LAB_UNSEAL_EQUALS_MASTER", "true")
	t.Setenv("KNXVAULT_ROOT_TOKEN", "integration-root")
	t.Setenv("KNXVAULT_JWT_SECRET", "jwt-test-secret")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() = %v", err)
	}

	deps, err := app.NewDependencies(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDependencies() = %v", err)
	}

	return api.NewRouter(zap.NewNop(), cfg.Version, false, api.RouterDeps{
		Ready:          deps,
		AuthService:    deps.AuthService,
		PKIService:     deps.PKIService,
		SecretsService: deps.SecretsService,
		TokenTTL:       deps.TokenTTL,
	}), "integration-root"
}

func TestIntegrationHealthAndMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router, _ := newTestRouter(t)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	for _, path := range []string{"/health", "/ready", "/metrics"} {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s = %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, resp.StatusCode)
		}
	}
}

func TestIntegrationSecretsRoundTrip(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router, token := newTestRouter(t)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	writeBody, _ := json.Marshal(map[string]any{
		"data": map[string]any{"password": "integration-secret"},
		"options": map[string]any{
			"ttl": "1h",
		},
	})
	req, err := http.NewRequest(http.MethodPost, server.URL+"/secrets/kv/app/integration", bytes.NewReader(writeBody))
	if err != nil {
		t.Fatalf("NewRequest() = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST secret = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST secret status = %d", resp.StatusCode)
	}

	readReq, err := http.NewRequest(http.MethodGet, server.URL+"/secrets/kv/app/integration", nil)
	if err != nil {
		t.Fatalf("NewRequest() = %v", err)
	}
	readReq.Header.Set("Authorization", "Bearer "+token)

	readResp, err := client.Do(readReq)
	if err != nil {
		t.Fatalf("GET secret = %v", err)
	}
	defer func() { _ = readResp.Body.Close() }()
	if readResp.StatusCode != http.StatusOK {
		t.Fatalf("GET secret status = %d", readResp.StatusCode)
	}

	var payload struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(readResp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode = %v", err)
	}
	if payload.Data["password"] != "integration-secret" {
		t.Fatalf("data = %v", payload.Data)
	}
}

func TestIntegrationAuthToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router, token := newTestRouter(t)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	body, _ := json.Marshal(map[string]string{"token": token})
	resp, err := http.Post(server.URL+"/auth/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/token = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/token status = %d", resp.StatusCode)
	}
}
