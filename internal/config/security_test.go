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

func TestValidateSecurityRejectsInsecureK8sWithoutLabFlag(t *testing.T) {
	cfg := config.Config{K8sAuthInsecure: true}
	if err := config.ValidateSecurity(cfg, ""); err == nil {
		t.Fatal("expected k8s_auth_insecure without lab flag to fail")
	}
	cfg.RaftAllowInsecure = true
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("lab escape: %v", err)
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

func TestValidateSecurityRequiresRaftMTLSForMultiNode(t *testing.T) {
	cfg := config.Config{
		Raft: config.RaftConfig{
			Enabled: true,
			InitialMembers: map[uint64]string{
				1: "127.0.0.1:63001",
				2: "127.0.0.1:63002",
			},
		},
		UnsealKey: "dGVzdA==",
	}
	if err := config.ValidateSecurity(cfg, ""); err == nil {
		t.Fatal("expected raft mTLS required")
	}
	cfg.RaftAllowInsecure = true
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("allow insecure: %v", err)
	}
	cfg.RaftAllowInsecure = false
	cfg.Raft.MTLSCertFile = "c"
	cfg.Raft.MTLSKeyFile = "k"
	cfg.Raft.MTLSCAFile = "ca"
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("with mTLS: %v", err)
	}
}
