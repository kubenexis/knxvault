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

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api"
	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/config"
)

func TestIntegrationSealBlocksKVWrite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	t.Setenv("KNXVAULT_MASTER_KEY", testMasterKey())
	t.Setenv("KNXVAULT_LAB_UNSEAL_EQUALS_MASTER", "true")
	t.Setenv("KNXVAULT_ROOT_TOKEN", "seal-test-root")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() = %v", err)
	}
	deps, err := app.NewDependencies(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDependencies() = %v", err)
	}
	defer deps.Close()

	router := api.NewRouter(zap.NewNop(), cfg.Version, false, api.RouterDeps{
		Ready:          deps,
		Seal:           deps.Seal,
		AuthService:    deps.AuthService,
		SecretsService: deps.SecretsService,
		TokenTTL:       deps.TokenTTL,
	})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	sealReq, _ := http.NewRequest(http.MethodPost, server.URL+"/sys/seal", nil)
	sealReq.Header.Set("Authorization", "Bearer seal-test-root")
	sealResp, err := http.DefaultClient.Do(sealReq)
	if err != nil {
		t.Fatalf("seal = %v", err)
	}
	_ = sealResp.Body.Close()

	body, _ := json.Marshal(map[string]any{"data": map[string]any{"x": 1}})
	putReq, _ := http.NewRequest(http.MethodPost, server.URL+"/secrets/kv/app/x", bytes.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer seal-test-root")
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("put = %v", err)
	}
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("PUT status = %d, want 503", putResp.StatusCode)
	}

	unsealBody, _ := json.Marshal(map[string]string{
		"key": base64.StdEncoding.EncodeToString(deps.MasterKey),
	})
	unsealReq, _ := http.NewRequest(http.MethodPost, server.URL+"/sys/unseal", bytes.NewReader(unsealBody))
	unsealReq.Header.Set("Content-Type", "application/json")
	unsealResp, err := http.DefaultClient.Do(unsealReq)
	if err != nil {
		t.Fatalf("unseal = %v", err)
	}
	_ = unsealResp.Body.Close()
	if unsealResp.StatusCode != http.StatusOK {
		t.Fatalf("unseal status = %d", unsealResp.StatusCode)
	}
}
