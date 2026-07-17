// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/backup"
	kvncrypto "github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/service/audithelper"
)

// SnapshotImporter replaces vault state from a portable snapshot.
type SnapshotImporter interface {
	ImportSnapshot(ctx context.Context, snapshot *backup.Snapshot) error
}

// SnapshotExporter performs an atomic snapshot export (Raft read path).
type SnapshotExporter interface {
	ExportSnapshot(ctx context.Context, opts backup.ExportOptions) (*backup.Snapshot, error)
}

// SnapshotRequester triggers an on-disk Dragonboat snapshot.
type SnapshotRequester interface {
	RequestSnapshot(ctx context.Context) error
}

// PolicyReloader refreshes the in-memory RBAC cache after restore.
type PolicyReloader interface {
	LoadIntoRBAC(ctx context.Context) error
}

// BackupService creates and restores encrypted vault snapshots.
type BackupService struct {
	repos     backup.Repos
	crypto    *kvncrypto.Service
	audit     *auditsvc.Service
	importer  SnapshotImporter
	exporter  SnapshotExporter
	snapshots SnapshotRequester
	policies  PolicyReloader
}

// NewBackupService constructs a backup service.
func NewBackupService(
	repos backup.Repos,
	cryptoSvc *kvncrypto.Service,
	audit *auditsvc.Service,
) *BackupService {
	return &BackupService{
		repos:  repos,
		crypto: cryptoSvc,
		audit:  audit,
	}
}

// SetSnapshotImporter configures Raft snapshot restore.
func (s *BackupService) SetSnapshotImporter(importer SnapshotImporter) {
	s.importer = importer
}

// SetSnapshotExporter configures atomic Raft snapshot export.
func (s *BackupService) SetSnapshotExporter(exporter SnapshotExporter) {
	s.exporter = exporter
}

// SetSnapshotRequester configures Dragonboat snapshot persistence after export.
func (s *BackupService) SetSnapshotRequester(requester SnapshotRequester) {
	s.snapshots = requester
}

// SetPolicyReloader configures RBAC reload after restore.
func (s *BackupService) SetPolicyReloader(reloader PolicyReloader) {
	s.policies = reloader
}

// Create exports and encrypts a backup archive.
func (s *BackupService) Create(ctx context.Context, opts backup.ExportOptions) ([]byte, error) {
	if s.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "master key required for encrypted backups")
	}
	var (
		snapshot *backup.Snapshot
		err      error
	)
	if s.exporter != nil {
		snapshot, err = s.exporter.ExportSnapshot(ctx, opts)
	} else {
		snapshot, err = backup.Export(ctx, s.repos, opts)
	}
	if err != nil {
		audithelper.Record(s.audit, ctx, "backup.create", "sys/backup", err, nil)
		return nil, err
	}
	if s.snapshots != nil {
		_ = s.snapshots.RequestSnapshot(ctx)
	}
	data, err := backup.Seal(s.crypto, snapshot)
	if err != nil {
		audithelper.Record(s.audit, ctx, "backup.create", "sys/backup", err, nil)
		return nil, err
	}
	audithelper.Record(s.audit, ctx, "backup.create", "sys/backup", nil, map[string]any{
		"cas":       len(snapshot.CAs),
		"secrets":   len(snapshot.Secrets),
		"pki_roles": len(snapshot.PKIRoles),
	})
	return data, nil
}

// Restore decrypts and imports a backup archive.
func (s *BackupService) Restore(ctx context.Context, data []byte) error {
	if s.crypto == nil {
		return common.New(common.ErrCodeInternal, "master key required for encrypted backups")
	}
	snapshot, err := backup.Open(s.crypto, data)
	if err != nil {
		audithelper.Record(s.audit, ctx, "backup.restore", "sys/restore", err, nil)
		return err
	}
	if err := backup.ValidateSnapshot(snapshot); err != nil {
		audithelper.Record(s.audit, ctx, "backup.restore", "sys/restore", err, nil)
		return err
	}
	if s.importer != nil {
		err = s.importer.ImportSnapshot(ctx, snapshot)
	} else {
		err = backup.Restore(ctx, s.repos, snapshot)
	}
	if err == nil && s.policies != nil {
		if reloadErr := s.policies.LoadIntoRBAC(ctx); reloadErr != nil {
			err = reloadErr
		}
	}
	audithelper.Record(s.audit, ctx, "backup.restore", "sys/restore", err, map[string]any{
		"cas":     len(snapshot.CAs),
		"secrets": len(snapshot.Secrets),
	})
	return err
}
