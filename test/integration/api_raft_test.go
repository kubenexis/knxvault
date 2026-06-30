package integration_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api"
	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/config"
)

func raftHTTPTestRouter(t *testing.T) (*gin.Engine, string, func()) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	addr := raftFreePort(t)
	base := t.TempDir()
	t.Setenv("KNXVAULT_RAFT_ENABLED", "true")
	t.Setenv("KNXVAULT_RAFT_NODE_ID", "1")
	t.Setenv("KNXVAULT_RAFT_ADDRESS", addr)
	t.Setenv("KNXVAULT_RAFT_DATA_DIR", filepath.Join(base, "raft"))
	t.Setenv("KNXVAULT_RAFT_INITIAL_MEMBERS", "1="+addr)
	t.Setenv("KNXVAULT_MASTER_KEY", testMasterKey())
	t.Setenv("KNXVAULT_ROOT_TOKEN", "raft-root")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() = %v", err)
	}
	deps, err := app.NewDependencies(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDependencies() = %v", err)
	}
	if deps.Raft == nil {
		t.Fatal("expected raft bundle")
	}
	waitRaftReady(t, deps.Raft)

	cleanup := func() { deps.Close() }
	router := api.NewRouter(zap.NewNop(), cfg.Version, false, api.RouterDeps{
		Ready:          deps,
		AuthService:    deps.AuthService,
		SecretsService: deps.SecretsService,
		BackupService:  deps.BackupService,
		TokenTTL:       deps.TokenTTL,
		HAStatus:       deps,
		IsLeader:       deps.IsLeader,
	})
	return router, "raft-root", cleanup
}

func TestIntegrationRaftHTTPSecretsRoundTrip(t *testing.T) {
	router, token, cleanup := raftHTTPTestRouter(t)
	defer cleanup()

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	body, _ := json.Marshal(map[string]any{
		"data": map[string]any{"token": "raft-secret"},
	})
	req, err := http.NewRequest(http.MethodPost, server.URL+"/secrets/kv/raft/app", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST secret = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d", resp.StatusCode)
	}

	getReq, err := http.NewRequest(http.MethodGet, server.URL+"/secrets/kv/raft/app", nil)
	if err != nil {
		t.Fatalf("NewRequest() = %v", err)
	}
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("GET secret = %v", err)
	}
	defer func() { _ = getResp.Body.Close() }()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d", getResp.StatusCode)
	}
}

func TestIntegrationRaftHTTPReady(t *testing.T) {
	router, _, cleanup := raftHTTPTestRouter(t)
	defer cleanup()

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/ready")
	if err != nil {
		t.Fatalf("GET /ready = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/ready status = %d", resp.StatusCode)
	}
}

func TestIntegrationRaftBackupCreate(t *testing.T) {
	router, token, cleanup := raftHTTPTestRouter(t)
	defer cleanup()

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	req, err := http.NewRequest(http.MethodPost, server.URL+"/sys/backup", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("NewRequest() = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST backup = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("backup status = %d", resp.StatusCode)
	}
	var payload struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(payload.Data); err != nil {
		t.Fatalf("backup data not base64: %v", err)
	}
}
