package config_test

import (
	"testing"

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
