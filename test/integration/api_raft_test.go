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
	"github.com/kubenexis/knxvault/internal/api/handlers"
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
	t.Setenv("KNXVAULT_UNSEAL_KEY", testUnsealKey())
	t.Setenv("KNXVAULT_ROOT_TOKEN", "raft-root")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() = %v", err)
	}
	deps, err := app.NewDependencies(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDependencies() = %v", err)
	}
	if deps.Seal != nil && deps.Seal.Sealed() {
		raw, err := base64.StdEncoding.DecodeString(testUnsealKey())
		if err != nil {
			t.Fatalf("decode unseal key: %v", err)
		}
		if !deps.Seal.Unseal(raw) {
			t.Fatal("expected unseal to succeed in raft integration test")
		}
	}
	if deps.Raft == nil {
		t.Fatal("expected raft bundle")
	}
	waitRaftReady(t, deps.Raft)

	cleanup := func() { deps.Close() }
	var raftMembership handlers.RaftMembership
	if deps.Raft != nil {
		raftMembership = deps.Raft.Client
	}
	router := api.NewRouter(zap.NewNop(), cfg.Version, false, api.RouterDeps{
		Ready:            deps,
		Seal:             deps.Seal,
		AuthService:      deps.AuthService,
		PKIService:       deps.PKIService,
		SecretsService:   deps.SecretsService,
		BackupService:    deps.BackupService,
		MasterKeyService: deps.MasterKeyService,
		RaftMembership:   raftMembership,
		MasterKey:        deps.MasterKey,
		TokenTTL:         deps.TokenTTL,
		HAStatus:         deps,
		IsLeader:         deps.IsLeader,
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

func TestIntegrationRaftHTTPPKIRoundTrip(t *testing.T) {
	router, token, cleanup := raftHTTPTestRouter(t)
	defer cleanup()

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	rootBody, _ := json.Marshal(map[string]any{
		"name":        "raft-http-root",
		"common_name": "Raft HTTP Root",
		"ttl":         "8760h",
	})
	rootReq, err := http.NewRequest(http.MethodPost, server.URL+"/pki/root", bytes.NewReader(rootBody))
	if err != nil {
		t.Fatalf("NewRequest() = %v", err)
	}
	rootReq.Header.Set("Authorization", "Bearer "+token)
	rootReq.Header.Set("Content-Type", "application/json")
	rootResp, err := http.DefaultClient.Do(rootReq)
	if err != nil {
		t.Fatalf("POST /pki/root = %v", err)
	}
	_ = rootResp.Body.Close()
	if rootResp.StatusCode != http.StatusOK && rootResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /pki/root status = %d", rootResp.StatusCode)
	}

	issueBody, _ := json.Marshal(map[string]any{
		"role":        "raft-http-root",
		"common_name": "app.example.com",
		"dns_names":   []string{"app.example.com"},
		"ttl":         "24h",
	})
	issueReq, err := http.NewRequest(http.MethodPost, server.URL+"/pki/issue", bytes.NewReader(issueBody))
	if err != nil {
		t.Fatalf("NewRequest() = %v", err)
	}
	issueReq.Header.Set("Authorization", "Bearer "+token)
	issueReq.Header.Set("Content-Type", "application/json")
	issueResp, err := http.DefaultClient.Do(issueReq)
	if err != nil {
		t.Fatalf("POST /pki/issue = %v", err)
	}
	defer func() { _ = issueResp.Body.Close() }()
	if issueResp.StatusCode != http.StatusOK && issueResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /pki/issue status = %d", issueResp.StatusCode)
	}
}
