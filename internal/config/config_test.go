package config_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/config"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("KNXVAULT_HTTP_ADDR", "")
	t.Setenv("KNXVAULT_LOG_LEVEL", "")
	t.Setenv("KNXVAULT_VERSION", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTPAddr != ":8200" {
		t.Errorf("HTTPAddr = %q, want :8200", cfg.HTTPAddr)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.Version != "0.4.5" {
		t.Errorf("Version = %q, want 0.4.5", cfg.Version)
	}
}

func TestLoadOpenSSL(t *testing.T) {
	t.Setenv("KNXVAULT_OPENSSL_BINARY", "/usr/bin/openssl")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.OpenSSLBinary != "/usr/bin/openssl" {
		t.Errorf("OpenSSLBinary = %q", cfg.OpenSSLBinary)
	}
}

func TestLoadInvalidShutdownGrace(t *testing.T) {
	t.Setenv("KNXVAULT_SHUTDOWN_GRACE", "not-a-duration")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for invalid KNXVAULT_SHUTDOWN_GRACE")
	}
}

func TestLoadCertRenewalAndSecurity(t *testing.T) {
	t.Setenv("KNXVAULT_JOB_CERT_RENEW_INTERVAL", "30m")
	t.Setenv("KNXVAULT_RENEW_GRACE", "48h")
	t.Setenv("KNXVAULT_RATE_LIMIT_ENABLED", "true")
	t.Setenv("KNXVAULT_RATE_LIMIT_RPM", "120")
	t.Setenv("KNXVAULT_REQUEST_SIGNING_KEY", "signing-secret")
	t.Setenv("KNXVAULT_REQUEST_SIGNING_REQUIRED", "true")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.JobCertRenewInterval != 30*time.Minute {
		t.Errorf("JobCertRenewInterval = %v, want 30m", cfg.JobCertRenewInterval)
	}
	if cfg.RenewGrace != 48*time.Hour {
		t.Errorf("RenewGrace = %v, want 48h", cfg.RenewGrace)
	}
	if !cfg.RateLimitEnabled {
		t.Error("RateLimitEnabled = false, want true")
	}
	if cfg.RateLimitRPM != 120 {
		t.Errorf("RateLimitRPM = %d, want 120", cfg.RateLimitRPM)
	}
	if cfg.RequestSigningKey != "signing-secret" {
		t.Errorf("RequestSigningKey = %q", cfg.RequestSigningKey)
	}
	if !cfg.RequestSigningRequired {
		t.Error("RequestSigningRequired = false, want true")
	}
}

func TestLoadTracing(t *testing.T) {
	t.Setenv("KNXVAULT_TRACING_ENABLED", "true")
	t.Setenv("KNXVAULT_OTLP_ENDPOINT", "otel-collector:4318")
	t.Setenv("KNXVAULT_TRACING_SAMPLE_RATIO", "0.5")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if !cfg.TracingEnabled {
		t.Error("TracingEnabled = false, want true")
	}
	if cfg.OTLPEndpoint != "otel-collector:4318" {
		t.Errorf("OTLPEndpoint = %q", cfg.OTLPEndpoint)
	}
	if cfg.TracingSampleRatio != 0.5 {
		t.Errorf("TracingSampleRatio = %v, want 0.5", cfg.TracingSampleRatio)
	}
}

func TestLoadRaft(t *testing.T) {
	t.Setenv("KNXVAULT_RAFT_ENABLED", "true")
	t.Setenv("KNXVAULT_RAFT_NODE_ID", "2")
	t.Setenv("KNXVAULT_RAFT_ADDRESS", "10.0.0.2:63001")
	t.Setenv("KNXVAULT_RAFT_DATA_DIR", "/tmp/raft")
	t.Setenv("KNXVAULT_RAFT_INITIAL_MEMBERS", "1=10.0.0.1:63001,2=10.0.0.2:63001")
	t.Setenv("KNXVAULT_RAFT_ELECTION_RTT", "12")
	t.Setenv("KNXVAULT_RAFT_HEARTBEAT_RTT", "2")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if !cfg.Raft.Enabled {
		t.Fatal("Raft.Enabled = false")
	}
	if cfg.Raft.NodeID != 2 {
		t.Errorf("Raft.NodeID = %d", cfg.Raft.NodeID)
	}
	if cfg.Raft.ElectionRTT != 12 || cfg.Raft.HeartbeatRTT != 2 {
		t.Errorf("raft RTT = %d/%d", cfg.Raft.ElectionRTT, cfg.Raft.HeartbeatRTT)
	}
}

func TestLoadRaftNodeIDFromPodName(t *testing.T) {
	t.Setenv("KNXVAULT_RAFT_ENABLED", "true")
	t.Setenv("KNXVAULT_RAFT_NODE_ID", "")
	t.Setenv("KNXVAULT_POD_NAME", "knxvault-2")
	t.Setenv("KNXVAULT_RAFT_ADDRESS", "127.0.0.1:63001")
	t.Setenv("KNXVAULT_RAFT_DATA_DIR", "/tmp/raft")
	t.Setenv("KNXVAULT_RAFT_INITIAL_MEMBERS", "1=127.0.0.1:63001,3=127.0.0.1:63003")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.Raft.NodeID != 3 {
		t.Fatalf("Raft.NodeID = %d, want 3 from knxvault-2", cfg.Raft.NodeID)
	}
}
