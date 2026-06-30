package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository/postgres"
)

func TestIntegrationPostgresSecretRepository(t *testing.T) {
	url := os.Getenv("KNXVAULT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("KNXVAULT_TEST_DATABASE_URL not set")
	}

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("NewPool() = %v", err)
	}
	t.Cleanup(pool.Close)

	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate() = %v", err)
	}

	repo := postgres.NewSecretRepository(pool)
	path := "integration/" + uuid.NewString()

	version, err := repo.NextVersion(ctx, path)
	if err != nil {
		t.Fatalf("NextVersion() = %v", err)
	}

	sv := &secrets.SecretVersion{
		ID:        uuid.New(),
		Path:      path,
		Version:   version,
		DataEnc:   []byte{9, 8, 7},
		DEKEnc:    []byte{6, 5, 4},
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.SaveVersion(ctx, sv); err != nil {
		t.Fatalf("SaveVersion() = %v", err)
	}

	got, err := repo.GetLatest(ctx, path)
	if err != nil {
		t.Fatalf("GetLatest() = %v", err)
	}
	if got.Version != version {
		t.Fatalf("version = %d, want %d", got.Version, version)
	}
}
