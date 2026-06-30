package app_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/config"
)

func TestNewDependenciesWithoutDatabase(t *testing.T) {
	t.Setenv("KNXVAULT_DATABASE_URL", "")
	t.Setenv("KNXVAULT_MASTER_KEY", "")
	t.Setenv("KNXVAULT_MASTER_KEY_FILE", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	deps, err := app.NewDependencies(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDependencies() = %v", err)
	}
	if deps.OpenSSL == nil {
		t.Fatal("expected OpenSSL wrapper")
	}
	if deps.Pool != nil {
		t.Fatal("expected no database pool")
	}
	if deps.AuthService == nil {
		t.Fatal("expected auth service")
	}
	if deps.CARepo == nil || deps.SecretRepo == nil {
		t.Fatal("expected in-memory repositories")
	}
}
