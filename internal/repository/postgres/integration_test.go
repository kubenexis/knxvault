package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/audit"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/postgres"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("KNXVAULT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("KNXVAULT_TEST_DATABASE_URL not set; skipping postgres integration test")
	}
	return url
}

func TestPostgresRepositoriesIntegration(t *testing.T) {
	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, testDatabaseURL(t))
	if err != nil {
		t.Fatalf("NewPool() = %v", err)
	}
	t.Cleanup(pool.Close)

	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate() = %v", err)
	}

	caRepo := postgres.NewCARepository(pool)
	secretRepo := postgres.NewSecretRepository(pool)
	auditRepo := postgres.NewAuditRepository(pool)

	ca := &pki.CA{
		ID:            uuid.New(),
		Name:          "integration-root-" + uuid.NewString(),
		Type:          pki.CATypeRoot,
		Serial:        "01",
		CertPEM:       "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		PrivateKeyEnc: []byte{1, 2, 3},
		DEKEnc:        []byte{4, 5, 6},
		Status:        pki.CAStatusActive,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour),
	}
	if err := caRepo.Save(ctx, ca); err != nil {
		t.Fatalf("Save(ca) = %v", err)
	}
	gotCA, err := caRepo.GetByName(ctx, ca.Name)
	if err != nil {
		t.Fatalf("GetByName(ca) = %v", err)
	}
	if gotCA.ID != ca.ID {
		t.Fatalf("ca id = %v, want %v", gotCA.ID, ca.ID)
	}

	path := "integration/" + uuid.NewString()
	next, err := secretRepo.NextVersion(ctx, path)
	if err != nil {
		t.Fatalf("NextVersion() = %v", err)
	}
	if next != 1 {
		t.Fatalf("NextVersion() = %d, want 1", next)
	}

	sv := &secrets.SecretVersion{
		ID:        uuid.New(),
		Path:      path,
		Version:   next,
		DataEnc:   []byte{9, 8, 7},
		DEKEnc:    []byte{6, 5, 4},
		CreatedAt: time.Now().UTC(),
	}
	if err := secretRepo.SaveVersion(ctx, sv); err != nil {
		t.Fatalf("SaveVersion() = %v", err)
	}
	latest, err := secretRepo.GetLatest(ctx, path)
	if err != nil {
		t.Fatalf("GetLatest() = %v", err)
	}
	if latest.Version != 1 {
		t.Fatalf("latest version = %d, want 1", latest.Version)
	}

	entry := &audit.Entry{
		Timestamp: time.Now().UTC(),
		Actor:     "integration",
		Action:    "secret.write",
		Resource:  path,
		Status:    "success",
		Details:   map[string]any{"version": 1},
	}
	if err := auditRepo.Append(ctx, entry); err != nil {
		t.Fatalf("Append() = %v", err)
	}
	entries, err := auditRepo.List(ctx, repository.AuditListOptions{Limit: 5})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected audit entries")
	}
}
