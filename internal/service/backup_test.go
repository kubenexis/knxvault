// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/backup"
	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestBackupServiceCreateRestore(t *testing.T) {
	ctx := context.Background()
	repos := testBackupRepos()
	cryptoSvc := testCrypto(t)
	svc := service.NewBackupService(repos, cryptoSvc, testAudit())

	caID := uuid.New()
	now := time.Now().UTC()
	if err := repos.CA.Save(ctx, &domainpki.CA{
		ID:            caID,
		Name:          "root",
		Type:          domainpki.CATypeRoot,
		Subject:       domainpki.DistinguishedName{CommonName: "Root"},
		Serial:        "01",
		CertPEM:       "pem",
		PrivateKeyEnc: []byte("key"),
		DEKEnc:        []byte("dek"),
		Status:        domainpki.CAStatusActive,
		CreatedAt:     now,
		ExpiresAt:     now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	secretID := uuid.New()
	if err := repos.Secret.SaveVersion(ctx, &secrets.SecretVersion{
		ID:        secretID,
		Path:      "app/db",
		Version:   1,
		DataEnc:   []byte("data"),
		DEKEnc:    []byte("dek"),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("SaveVersion() = %v", err)
	}

	archive, err := svc.Create(ctx, backup.ExportOptions{})
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if len(archive) == 0 {
		t.Fatal("expected non-empty archive")
	}

	restoreRepos := testBackupRepos()
	restoreSvc := service.NewBackupService(restoreRepos, cryptoSvc, testAudit())
	if err := restoreSvc.Restore(ctx, archive); err != nil {
		t.Fatalf("Restore() = %v", err)
	}

	cas, err := restoreRepos.CA.List(ctx)
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(cas) != 1 {
		t.Fatalf("cas = %d, want 1", len(cas))
	}
}

func TestBackupServiceRequiresCrypto(t *testing.T) {
	ctx := context.Background()
	svc := service.NewBackupService(testBackupRepos(), nil, nil)

	if _, err := svc.Create(ctx, backup.ExportOptions{}); err == nil {
		t.Fatal("expected Create() error without crypto")
	}
	if err := svc.Restore(ctx, []byte("data")); err == nil {
		t.Fatal("expected Restore() error without crypto")
	}
}

type snapshotStub struct {
	snapshot *backup.Snapshot
	err      error
	called   bool
}

func (s *snapshotStub) ExportSnapshot(_ context.Context, _ backup.ExportOptions) (*backup.Snapshot, error) {
	s.called = true
	return s.snapshot, s.err
}

func (s *snapshotStub) ImportSnapshot(_ context.Context, _ *backup.Snapshot) error {
	s.called = true
	return s.err
}

func (s *snapshotStub) RequestSnapshot(_ context.Context) error {
	s.called = true
	return s.err
}

func TestBackupServiceUsesExporterAndImporter(t *testing.T) {
	ctx := context.Background()
	cryptoSvc := testCrypto(t)
	snapshot := &backup.Snapshot{Version: 1}
	exporter := &snapshotStub{snapshot: snapshot}
	importer := &snapshotStub{}
	requester := &snapshotStub{}

	svc := service.NewBackupService(testBackupRepos(), cryptoSvc, testAudit())
	svc.SetSnapshotExporter(exporter)
	svc.SetSnapshotRequester(requester)

	archive, err := svc.Create(ctx, backup.ExportOptions{})
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if !exporter.called || !requester.called {
		t.Fatal("expected exporter and requester to be called")
	}

	restoreSvc := service.NewBackupService(testBackupRepos(), cryptoSvc, testAudit())
	restoreSvc.SetSnapshotImporter(importer)
	if err := restoreSvc.Restore(ctx, archive); err != nil {
		t.Fatalf("Restore() = %v", err)
	}
	if !importer.called {
		t.Fatal("expected importer to be called")
	}
}
