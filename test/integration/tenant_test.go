package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/api"
	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/config"
)

func newTenantRouter(t *testing.T, tenantMode bool) (*gin.Engine, string) {
	t.Helper()
	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	t.Setenv("KNXVAULT_MASTER_KEY", testMasterKey())
	t.Setenv("KNXVAULT_ROOT_TOKEN", "integration-root")
	t.Setenv("KNXVAULT_JWT_SECRET", "jwt-test-secret")
	if tenantMode {
		t.Setenv("KNXVAULT_TENANT_MODE", "true")
	} else {
		t.Setenv("KNXVAULT_TENANT_MODE", "false")
	}

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
		SecretsService: deps.SecretsService,
		TokenTTL:       deps.TokenTTL,
		TenantMode:     cfg.TenantMode,
	}), "integration-root"
}

func TestIntegrationTenantModeMatrix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name       string
		tenantMode bool
		namespace  string
		wantStatus int
	}{
		{"off_without_namespace", false, "", http.StatusOK},
		{"on_with_namespace", true, "team-a", http.StatusOK},
		{"on_without_namespace", true, "", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, token := newTenantRouter(t, tc.tenantMode)
			server := httptest.NewServer(router)
			t.Cleanup(server.Close)

			body, _ := json.Marshal(map[string]any{
				"data": map[string]any{"secret": "tenant-value"},
			})
			req, err := http.NewRequest(http.MethodPost, server.URL+"/secrets/kv/app/tenant", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("NewRequest() = %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			if tc.namespace != "" {
				req.Header.Set(auth.NamespaceHeader, tc.namespace)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do() = %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d want %d", resp.StatusCode, tc.wantStatus)
			}
		})
	}
}
