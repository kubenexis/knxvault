package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/config"
)

func TestLoadFileBaseWithEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "knxvault.yaml")
	if err := os.WriteFile(path, []byte(`---
http_addr: ":9200"
log_level: debug
raft:
  enabled: true
  node_id: 2
  address: "10.0.0.2:63001"
  data_dir: /tmp/raft
  election_rtt: 12
  heartbeat_rtt: 2
`), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}

	t.Setenv("KNXVAULT_HTTP_ADDR", ":8300")
	t.Setenv("KNXVAULT_RAFT_INITIAL_MEMBERS", "1=10.0.0.1:63001,2=10.0.0.2:63001")

	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() = %v", err)
	}
	if cfg.HTTPAddr != ":8300" {
		t.Fatalf("HTTPAddr = %q, want env override :8300", cfg.HTTPAddr)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q, want debug from file", cfg.LogLevel)
	}
	if !cfg.Raft.Enabled || cfg.Raft.NodeID != 2 {
		t.Fatalf("raft = %+v", cfg.Raft)
	}
	if cfg.Raft.ElectionRTT != 12 || cfg.Raft.HeartbeatRTT != 2 {
		t.Fatalf("raft RTT = %d/%d", cfg.Raft.ElectionRTT, cfg.Raft.HeartbeatRTT)
	}
}

func TestLoadFileInvalidDuration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("shutdown_grace: not-a-duration\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}
	if _, err := config.LoadFile(path); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadFileJobsSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs.yaml")
	if err := os.WriteFile(path, []byte(`---
jobs:
  cert_renew_interval: 30m
  renew_grace: 48h
`), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() = %v", err)
	}
	if cfg.JobCertRenewInterval != 30*time.Minute {
		t.Fatalf("JobCertRenewInterval = %v", cfg.JobCertRenewInterval)
	}
	if cfg.RenewGrace != 48*time.Hour {
		t.Fatalf("RenewGrace = %v", cfg.RenewGrace)
	}
}
