package service

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/backup"
	kvncrypto "github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// BackupService creates and restores encrypted vault snapshots.
type BackupService struct {
	repos  backup.Repos
	pool   *pgxpool.Pool
	crypto *kvncrypto.Service
	audit  *auditsvc.Service
}

// NewBackupService constructs a backup service.
func NewBackupService(
	repos backup.Repos,
	pool *pgxpool.Pool,
	cryptoSvc *kvncrypto.Service,
	audit *auditsvc.Service,
) *BackupService {
	return &BackupService{
		repos:  repos,
		pool:   pool,
		crypto: cryptoSvc,
		audit:  audit,
	}
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
	data, err := backup.Seal(s.crypto, snapshot)
	s.record(ctx, "backup.create", "sys/backup", err, map[string]any{
		"cas":     len(snapshot.CAs),
		"secrets": len(snapshot.Secrets),
	})
	return data, err
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
	err = backup.Restore(ctx, s.repos, s.pool, snapshot)
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
