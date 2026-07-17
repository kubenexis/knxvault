// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package backup_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/backup"
	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/audit"
	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func testCrypto(t *testing.T) *crypto.Service {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	svc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	return svc
}

func TestExportSealOpenRestore(t *testing.T) {
	ctx := context.Background()
	caRepo := memory.NewCARepository()
	secretRepo := memory.NewSecretRepository()
	policyRepo := memory.NewPolicyRepository()
	roleRepo := memory.NewRoleRepository()
	leaseRepo := memory.NewLeaseRepository()
	issuedRepo := memory.NewIssuedCertRepository()
	revokeRepo := memory.NewRevocationRepository()

	caID := uuid.New()
	now := time.Now().UTC()
	if err := caRepo.Save(ctx, &domainpki.CA{
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
	if err := secretRepo.SaveVersion(ctx, &secrets.SecretVersion{
		ID:        secretID,
		Path:      "app/db",
		Version:   1,
		DataEnc:   []byte("data"),
		DEKEnc:    []byte("dek"),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("SaveVersion() = %v", err)
	}

	source := backup.Repos{
		CA:         caRepo,
		Secret:     secretRepo,
		Revoke:     revokeRepo,
		Lease:      leaseRepo,
		Policy:     policyRepo,
		Role:       roleRepo,
		IssuedCert: issuedRepo,
	}

	snapshot, err := backup.Export(ctx, source, backup.ExportOptions{})
	if err != nil {
		t.Fatalf("Export() = %v", err)
	}
	if len(snapshot.CAs) != 1 || len(snapshot.Secrets) != 1 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}

	cryptoSvc := testCrypto(t)
	archive, err := backup.Seal(cryptoSvc, snapshot)
	if err != nil {
		t.Fatalf("Seal() = %v", err)
	}

	opened, err := backup.Open(cryptoSvc, archive)
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}

	targetCA := memory.NewCARepository()
	targetSecret := memory.NewSecretRepository()
	target := backup.Repos{
		CA:         targetCA,
		Secret:     targetSecret,
		Revoke:     memory.NewRevocationRepository(),
		Lease:      memory.NewLeaseRepository(),
		Policy:     memory.NewPolicyRepository(),
		Role:       memory.NewRoleRepository(),
		IssuedCert: memory.NewIssuedCertRepository(),
	}
	if err := backup.Restore(ctx, target, opened); err != nil {
		t.Fatalf("Restore() = %v", err)
	}

	cas, err := targetCA.List(ctx)
	if err != nil || len(cas) != 1 {
		t.Fatalf("restored cas = %v, %v", cas, err)
	}
	secretsList, err := targetSecret.ListByPath(ctx, "")
	if err != nil || len(secretsList) != 1 {
		t.Fatalf("restored secrets = %v, %v", secretsList, err)
	}
}

func TestRestoreAuditEntries(t *testing.T) {
	ctx := context.Background()
	auditRepo := memory.NewAuditRepository()
	now := time.Now().UTC()
	entry := &audit.Entry{
		Timestamp: now,
		Actor:     "admin",
		Action:    "kv.read",
		Resource:  "app/db",
		Status:    "success",
	}
	entry.Hash = auditsvc.EntryHash("", entry.Actor, entry.Action, entry.Resource, entry.Status, entry.Details, entry.Timestamp)
	if err := auditRepo.Append(ctx, entry); err != nil {
		t.Fatalf("Append() = %v", err)
	}

	source := backup.Repos{
		CA:     memory.NewCARepository(),
		Secret: memory.NewSecretRepository(),
		Audit:  auditRepo,
	}
	snapshot, err := backup.Export(ctx, source, backup.ExportOptions{IncludeAudit: true})
	if err != nil {
		t.Fatalf("Export() = %v", err)
	}
	if len(snapshot.Audit) != 1 {
		t.Fatalf("audit records = %d", len(snapshot.Audit))
	}

	targetAudit := memory.NewAuditRepository()
	target := backup.Repos{
		CA:     memory.NewCARepository(),
		Secret: memory.NewSecretRepository(),
		Audit:  targetAudit,
	}
	if err := backup.Restore(ctx, target, snapshot); err != nil {
		t.Fatalf("Restore() = %v", err)
	}

	entries, err := targetAudit.List(ctx, repository.AuditListOptions{OrderAsc: true})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("restored audit entries = %d", len(entries))
	}
	if entries[0].Hash != entry.Hash || entries[0].Action != "kv.read" {
		t.Fatalf("unexpected entry: %+v", entries[0])
	}
}
