package backup_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/backup"
	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestValidateSnapshotRejectsUnknownParent(t *testing.T) {
	parent := uuid.New()
	snapshot := &backup.Snapshot{
		Version: 1,
		CAs: []backup.CARecord{{
			ID:   uuid.New(),
			Name: "child",
			ParentID: func() *uuid.UUID {
				id := parent
				return &id
			}(),
		}},
	}
	if err := backup.ValidateSnapshot(snapshot); err == nil {
		t.Fatal("expected validation error for unknown parent")
	}
}

func TestValidateSnapshotRejectsUnknownPKICA(t *testing.T) {
	snapshot := &backup.Snapshot{
		Version: 1,
		CAs: []backup.CARecord{{
			ID:   uuid.New(),
			Name: "root",
		}},
		PKIRoles: []backup.PKIRoleRecord{{
			Name:   "web",
			CAName: "missing",
		}},
	}
	if err := backup.ValidateSnapshot(snapshot); err == nil {
		t.Fatal("expected validation error for unknown pki role ca")
	}
}

func TestValidateSnapshotRejectsBrokenAuditChain(t *testing.T) {
	snapshot := &backup.Snapshot{
		Version: 1,
		Audit: []backup.AuditRecord{{
			Timestamp: time.Now().UTC(),
			Actor:     "admin",
			Action:    "kv.read",
			Resource:  "app/db",
			Status:    "success",
			Hash:      "invalid",
		}},
	}
	if err := backup.ValidateSnapshot(snapshot); err == nil {
		t.Fatal("expected audit chain validation error")
	}
}

func TestRestoreReplacesExistingState(t *testing.T) {
	ctx := context.Background()
	caRepo := memory.NewCARepository()
	secretRepo := memory.NewSecretRepository()
	now := time.Now().UTC()
	_ = secretRepo.SaveVersion(ctx, &secrets.SecretVersion{
		ID:        uuid.New(),
		Path:      "stale",
		Version:   1,
		DataEnc:   []byte("old"),
		DEKEnc:    []byte("dek"),
		CreatedAt: now,
	})

	snapshot := &backup.Snapshot{
		Version: 1,
		Secrets: []backup.SecretRecord{{
			ID:        uuid.New(),
			Path:      "fresh",
			Version:   1,
			DataEnc:   []byte("new"),
			DEKEnc:    []byte("dek"),
			CreatedAt: now,
		}},
	}
	target := backup.Repos{CA: caRepo, Secret: secretRepo}
	if err := backup.Restore(ctx, target, snapshot); err != nil {
		t.Fatalf("Restore() = %v", err)
	}
	versions, err := secretRepo.ListByPath(ctx, "")
	if err != nil {
		t.Fatalf("ListByPath() = %v", err)
	}
	if len(versions) != 1 || versions[0].Path != "fresh" {
		t.Fatalf("unexpected secrets after replace restore: %+v", versions)
	}
}

func TestPKIRoleRoundTrip(t *testing.T) {
	ctx := context.Background()
	caRepo := memory.NewCARepository()
	pkiRoleRepo := memory.NewPKIRoleRepository()
	now := time.Now().UTC()

	caID := uuid.New()
	if err := caRepo.Save(ctx, &domainpki.CA{
		ID:            caID,
		Name:          "root",
		Type:          domainpki.CATypeRoot,
		Serial:        "01",
		CertPEM:       "pem",
		PrivateKeyEnc: []byte("key"),
		DEKEnc:        []byte("dek"),
		Status:        domainpki.CAStatusActive,
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	if err := pkiRoleRepo.Save(ctx, &domainpki.Role{
		Name:           "web",
		CAName:         "root",
		AllowedDomains: []string{"example.com"},
		MaxTTLSeconds:  3600,
		KeyUsage:       domainpki.RoleUsageServer,
	}); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	source := backup.Repos{
		CA:      caRepo,
		Secret:  memory.NewSecretRepository(),
		PKIRole: pkiRoleRepo,
	}
	snapshot, err := backup.Export(ctx, source, backup.ExportOptions{})
	if err != nil {
		t.Fatalf("Export() = %v", err)
	}
	if len(snapshot.PKIRoles) != 1 {
		t.Fatalf("PKIRoles = %d, want 1", len(snapshot.PKIRoles))
	}

	targetPKI := memory.NewPKIRoleRepository()
	target := backup.Repos{
		CA:      memory.NewCARepository(),
		Secret:  memory.NewSecretRepository(),
		PKIRole: targetPKI,
	}
	if err := backup.Restore(ctx, target, snapshot); err != nil {
		t.Fatalf("Restore() = %v", err)
	}
	role, err := targetPKI.Get(ctx, "web")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if role.CAName != "root" {
		t.Fatalf("CAName = %q, want root", role.CAName)
	}
}
