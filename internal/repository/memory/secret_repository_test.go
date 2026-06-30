package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestSecretRepositoryVersions(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewSecretRepository()

	next, err := repo.NextVersion(ctx, "app/db")
	if err != nil {
		t.Fatalf("NextVersion() = %v", err)
	}
	if next != 1 {
		t.Fatalf("NextVersion() = %d, want 1", next)
	}

	v1 := &secrets.SecretVersion{
		ID:        uuid.New(),
		Path:      "app/db",
		Version:   1,
		DataEnc:   []byte{1},
		DEKEnc:    []byte{2},
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.SaveVersion(ctx, v1); err != nil {
		t.Fatalf("SaveVersion(v1) = %v", err)
	}

	v2 := &secrets.SecretVersion{
		ID:        uuid.New(),
		Path:      "app/db",
		Version:   2,
		DataEnc:   []byte{3},
		DEKEnc:    []byte{4},
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.SaveVersion(ctx, v2); err != nil {
		t.Fatalf("SaveVersion(v2) = %v", err)
	}

	latest, err := repo.GetLatest(ctx, "app/db")
	if err != nil {
		t.Fatalf("GetLatest() = %v", err)
	}
	if latest.Version != 2 {
		t.Fatalf("latest version = %d, want 2", latest.Version)
	}

	list, err := repo.ListByPath(ctx, "app/")
	if err != nil {
		t.Fatalf("ListByPath() = %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("len(ListByPath()) = %d, want 2", len(list))
	}
}
