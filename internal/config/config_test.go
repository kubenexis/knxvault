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
	if cfg.Version != "0.1.0-dev" {
		t.Errorf("Version = %q, want 0.1.0-dev", cfg.Version)
	}
}

func TestLoadDatabaseAndOpenSSL(t *testing.T) {
	t.Setenv("KNXVAULT_DATABASE_URL", "postgres://localhost/knxvault")
	t.Setenv("KNXVAULT_OPENSSL_BINARY", "/usr/bin/openssl")
	t.Setenv("KNXVAULT_AUTO_MIGRATE", "false")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.DatabaseURL != "postgres://localhost/knxvault" {
		t.Errorf("DatabaseURL = %q", cfg.DatabaseURL)
	}
	if cfg.OpenSSLBinary != "/usr/bin/openssl" {
		t.Errorf("OpenSSLBinary = %q", cfg.OpenSSLBinary)
	}
	if cfg.AutoMigrate {
		t.Error("AutoMigrate = true, want false")
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
