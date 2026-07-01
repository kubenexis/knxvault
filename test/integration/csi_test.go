//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubenexis/knxvault/internal/inject/csi"
	provider "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

func TestCSIProviderMountIntegration(t *testing.T) {
	var auditRecorded bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/kubernetes":
			_ = json.NewEncoder(w).Encode(map[string]any{"client_token": "client-token", "policies": []string{"app"}})
		case "/secrets/kv/app/db":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":     map[string]any{"username": "app", "password": "pw"},
				"metadata": map[string]any{"version": 1},
			})
		case "/inject/csi/mount-audit":
			auditRecorded = true
			if auth := r.Header.Get("Authorization"); auth != "Bearer client-token" {
				http.Error(w, "missing mount token", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	srv := csi.NewServer(&csi.VaultClient{HTTP: api.Client()})
	attrs, _ := json.Marshal(map[string]string{
		"vaultAddr":                              api.URL,
		"role":                                   "app-sa",
		"objects":                                "- path: app/db\n  fileName: db.env\n  objectType: secret\n",
		"csi.storage.k8s.io/pod.name":            "workload-0",
		"csi.storage.k8s.io/pod.namespace":       "prod",
		"csi.storage.k8s.io/serviceAccount.name": "my-app",
	})
	secrets, _ := json.Marshal(map[string]string{"serviceAccountToken": "integration-jwt"})
	resp, err := srv.Mount(context.Background(), &provider.MountRequest{
		Attributes: string(attrs),
		Secrets:    string(secrets),
	})
	if err != nil {
		t.Fatalf("Mount() = %v", err)
	}
	if len(resp.Files) != 1 {
		t.Fatalf("files = %d", len(resp.Files))
	}
	contents := string(resp.Files[0].Contents)
	if !strings.Contains(contents, "password=pw") || !strings.Contains(contents, "username=app") {
		t.Fatalf("unexpected file contents: %q", contents)
	}
	if !auditRecorded {
		t.Fatal("expected csi.mount audit call")
	}
}
