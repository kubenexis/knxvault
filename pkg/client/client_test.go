package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubenexis/knxvault/pkg/client"
)

func TestHealthAndKV(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "version": "test"})
		case "/secrets/kv/app/db":
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Fatalf("missing auth header")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"password": "x"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := client.New(srv.URL, "tok")
	health, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() = %v", err)
	}
	if health.Status != "healthy" {
		t.Fatalf("status = %q", health.Status)
	}

	resp, err := c.KVGet(context.Background(), "app/db")
	if err != nil {
		t.Fatalf("KVGet() = %v", err)
	}
	if resp.Data["password"] != "x" {
		t.Fatalf("data = %+v", resp.Data)
	}
}
