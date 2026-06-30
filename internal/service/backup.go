package service

import (
	"context"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/backup"
	kvncrypto "github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// SnapshotImporter replaces vault state from a portable snapshot.
type SnapshotImporter interface {
	ImportSnapshot(ctx context.Context, snapshot *backup.Snapshot) error
}

// SnapshotRequester triggers an on-disk Dragonboat snapshot.
type SnapshotRequester interface {
	RequestSnapshot(ctx context.Context) error
}

// BackupService creates and restores encrypted vault snapshots.
type BackupService struct {
	repos     backup.Repos
	crypto    *kvncrypto.Service
	audit     *auditsvc.Service
	importer  SnapshotImporter
	snapshots SnapshotRequester
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

// SetSnapshotRequester configures Dragonboat snapshot persistence after export.
func (s *BackupService) SetSnapshotRequester(requester SnapshotRequester) {
	s.snapshots = requester
}

func (s *BackupService) actor(ctx context.Context) string {
	if principal, ok := auth.PrincipalFromContext(ctx); ok {
		return principal.Subject
	}
	return "anonymous"
}

// Create exports and encrypts a backup archive.
func (s *BackupService) Create(ctx context.Context, opts backup.ExportOptions) ([]byte, error) {
	if s.crypto == nil {
		return nil, common.New(common.ErrCodeInternal, "master key required for encrypted backups")
	}
	snapshot, err := backup.Export(ctx, s.repos, opts)
	if err != nil {
		s.record(ctx, "backup.create", "sys/backup", err, nil)
		return nil, err
	}
	if s.snapshots != nil {
		_ = s.snapshots.RequestSnapshot(ctx)
	}
	data, err := backup.Seal(s.crypto, snapshot)
	if err != nil {
		s.record(ctx, "backup.create", "sys/backup", err, nil)
		return nil, err
	}
	s.record(ctx, "backup.create", "sys/backup", nil, map[string]any{
		"cas":     len(snapshot.CAs),
		"secrets": len(snapshot.Secrets),
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
		s.record(ctx, "backup.restore", "sys/restore", err, nil)
		return err
	}
	if s.importer != nil {
		err = s.importer.ImportSnapshot(ctx, snapshot)
	} else {
		err = backup.Restore(ctx, s.repos, snapshot)
	}
	s.record(ctx, "backup.restore", "sys/restore", err, map[string]any{
		"cas":     len(snapshot.CAs),
		"secrets": len(snapshot.Secrets),
	})
	return err
}

func (s *BackupService) record(ctx context.Context, action, resource string, err error, details map[string]any) {
	if s.audit == nil {
		return
	}
	status := "success"
	if err != nil {
		status = "failure"
	}
	_ = s.audit.Record(ctx, s.actor(ctx), action, resource, status, details)
}