package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubenexis/knxvault/internal/config"
)

func TestValidateSecurityRejectsInsecureK8sWithRaft(t *testing.T) {
	cfg := config.Config{
		Raft:            config.RaftConfig{Enabled: true},
		K8sAuthInsecure: true,
		UnsealKey:       "dGVzdA==",
	}
	if err := config.ValidateSecurity(cfg, ""); err == nil {
		t.Fatal("expected error for insecure k8s auth with raft")
	}
}

func TestValidateSecurityRejectsWorldReadableConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "knxvault.conf")
	if err := os.WriteFile(path, []byte("http_addr: :8200\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg := config.Config{}
	if err := config.ValidateSecurity(cfg, path); err == nil {
		t.Fatal("expected permission error for world-readable config")
	}
}