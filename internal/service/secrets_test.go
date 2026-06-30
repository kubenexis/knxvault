package service_test

import (
	"context"
	"testing"

	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestSecretsServiceRoundTrip(t *testing.T) {
	cryptoSvc := testCrypto(t)
	engine := secretsengine.NewKVV2Engine(memory.NewSecretRepository(), cryptoSvc)
	svc := service.NewSecretsService(engine, testAudit())
	ctx := context.Background()

	put, err := svc.Put(ctx, "app/config", map[string]any{"token": "abc"}, secretsengine.PutOptions{})
	if err != nil {
		t.Fatalf("Put() = %v", err)
	}
	if put.Version != 1 {
		t.Fatalf("version = %d, want 1", put.Version)
	}

	got, err := svc.Get(ctx, "app/config")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if got.Data["token"] != "abc" {
		t.Fatalf("data = %v", got.Data)
	}

	gotVer, err := svc.GetVersion(ctx, "app/config", 1)
	if err != nil {
		t.Fatalf("GetVersion() = %v", err)
	}
	if gotVer.Data["token"] != "abc" {
		t.Fatalf("version data = %v", gotVer.Data)
	}

	paths, err := svc.ListPaths(ctx, "app/")
	if err != nil {
		t.Fatalf("ListPaths() = %v", err)
	}
	if len(paths) != 1 || paths[0] != "app/config" {
		t.Fatalf("paths = %v", paths)
	}

	versions, err := svc.ListVersions(ctx, "app/config")
	if err != nil {
		t.Fatalf("ListVersions() = %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("versions = %v", versions)
	}

	meta, err := svc.GetMetadata(ctx, "app/config", 1)
	if err != nil {
		t.Fatalf("GetMetadata() = %v", err)
	}
	if meta.Path != "app/config" {
		t.Fatalf("metadata path = %q", meta.Path)
	}

	if _, err := svc.Put(ctx, "app/config", map[string]any{"token": "v2"}, secretsengine.PutOptions{}); err != nil {
		t.Fatalf("Put() v2 = %v", err)
	}
	if err := svc.DestroyVersion(ctx, "app/config", 1); err != nil {
		t.Fatalf("DestroyVersion() = %v", err)
	}
	if err := svc.Delete(ctx, "app/config"); err != nil {
		t.Fatalf("Delete() = %v", err)
	}
}
