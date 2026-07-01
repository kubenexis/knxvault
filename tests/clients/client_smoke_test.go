package clients_test

import (
	"context"
	"os"
	"testing"

	"github.com/kubenexis/knxvault/pkg/client"
)

func TestGoClientHealthOffline(t *testing.T) {
	c := client.New("http://127.0.0.1:1", "")
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("expected connection error against closed port")
	}
}

func TestGoClientSmoke(t *testing.T) {
	if os.Getenv("KNXVAULT_SMOKE") != "1" {
		t.Skip("set KNXVAULT_SMOKE=1 for live smoke test")
	}
	token := os.Getenv("KNXVAULT_TOKEN")
	if token == "" {
		t.Skip("KNXVAULT_TOKEN required for smoke test")
	}
	c := client.New(os.Getenv("KNXVAULT_ADDR"), token)
	ctx := context.Background()
	if _, err := c.Health(ctx); err != nil {
		t.Fatalf("Health() = %v", err)
	}
	if err := c.KVPut(ctx, "clients/smoke", map[string]any{"ok": true}); err != nil {
		t.Fatalf("KVPut() = %v", err)
	}
	if _, err := c.KVGet(ctx, "clients/smoke"); err != nil {
		t.Fatalf("KVGet() = %v", err)
	}
}