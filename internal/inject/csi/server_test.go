package csi_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/inject/csi"
	provider "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

func TestServerMount(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/kubernetes":
			_ = json.NewEncoder(w).Encode(map[string]any{"client_token": "client-token"})
		case "/secrets/kv/app/db":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"password": "s3cret"},
				"metadata": map[string]any{"version": 3},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	srv := csi.NewServer(&csi.VaultClient{HTTP: api.Client()})
	attrs, _ := json.Marshal(map[string]string{
		"vaultAddr": api.URL,
		"role":      "app-sa",
		"objects":   "- path: app/db\n  fileName: db.env\n",
	})
	secrets, _ := json.Marshal(map[string]string{"serviceAccountToken": "sa-jwt"})
	resp, err := srv.Mount(context.Background(), &provider.MountRequest{
		Attributes: string(attrs),
		Secrets:    string(secrets),
	})
	if err != nil {
		t.Fatalf("Mount() = %v", err)
	}
	if len(resp.Files) != 1 || string(resp.Files[0].Contents) != "s3cret" {
		t.Fatalf("unexpected files: %+v", resp.Files)
	}
	if len(resp.ObjectVersion) != 1 || resp.ObjectVersion[0].Version != "3" {
		t.Fatalf("unexpected versions: %+v", resp.ObjectVersion)
	}
}

func TestServerRotationCounter(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/kubernetes":
			_ = json.NewEncoder(w).Encode(map[string]any{"client_token": "client-token"})
		case "/secrets/kv/app/db":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"password": "new"},
				"metadata": map[string]any{"version": 4},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	srv := csi.NewServer(&csi.VaultClient{HTTP: api.Client()})
	attrs, _ := json.Marshal(map[string]string{
		"vaultAddr": api.URL,
		"role":      "app-sa",
		"objects":   "- path: app/db\n  fileName: db.env\n",
	})
	secrets, _ := json.Marshal(map[string]string{"serviceAccountToken": "sa-jwt"})
	req := &provider.MountRequest{
		Attributes: string(attrs),
		Secrets:    string(secrets),
		CurrentObjectVersion: []*provider.ObjectVersion{
			{Id: "db.env", Version: "3"},
		},
	}
	if _, err := srv.Mount(context.Background(), req); err != nil {
		t.Fatalf("Mount() = %v", err)
	}
	if srv.Rotations() != 1 {
		t.Fatalf("rotations = %d, want 1", srv.Rotations())
	}
}

func TestServerServeBindsSocket(t *testing.T) {
	dir := t.TempDir()
	socket := dir + "/knxvault.sock"
	srv := csi.NewServer(csi.NewVaultClient())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		close(ready)
		errCh <- srv.Serve(ctx, socket)
	}()
	<-ready
	deadline := time.Now().Add(2 * time.Second)
	var conn net.Conn
	var err error
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", socket)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial socket: %v", err)
	}
	_ = conn.Close()
	cancel()
	<-errCh
}