package app

import (
	"context"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/infra/leader"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/service"
)

// JobRunner executes background maintenance tasks on the elected leader.
type JobRunner struct {
	leader            leader.Elector
	database          *service.DatabaseService
	pki               *service.PKIService
	rotation          *service.RotationService
	masterKey         *service.MasterKeyService
	cas               repository.CARepository
	leases            repository.LeaseRepository
	cfg               config.Config
	log               *zap.Logger
	electionRunning   atomic.Bool
	started           atomic.Bool
}

// NewJobRunner constructs a background job runner.
func NewJobRunner(
	elector leader.Elector,
	database *service.DatabaseService,
	pki *service.PKIService,
	rotation *service.RotationService,
	masterKey *service.MasterKeyService,
	cas repository.CARepository,
	leases repository.LeaseRepository,
	cfg config.Config,
	log *zap.Logger,
) *JobRunner {
	return &JobRunner{
		leader:    elector,
		database:  database,
		pki:       pki,
		rotation:  rotation,
		masterKey: masterKey,
		cas:       cas,
		leases:    leases,
		cfg:       cfg,
		log:       log,
	}
}

// ElectionRunning reports whether the leader election loop is active.
func (j *JobRunner) ElectionRunning() bool {
	if j == nil {
		return true
	}
	if !j.started.Load() {
		return true
	}
	return j.electionRunning.Load()
}

// Started reports whether Start has been invoked.
func (j *JobRunner) Started() bool {
	return j != nil && j.started.Load()
}

// Start launches leader election and periodic jobs.
func (j *JobRunner) Start(ctx context.Context) {
	if j == nil || j.leader == nil {
		return
	}
	go func() {
		j.started.Store(true)
		j.electionRunning.Store(true)
		metrics.SetLeaderElectionRunning(true)
		if err := j.leader.Run(ctx, j.runOnLeader); err != nil && ctx.Err() == nil {
			j.log.Error("leader election stopped", zap.Error(err))
		}
		j.electionRunning.Store(false)
		metrics.SetLeaderElectionRunning(false)
		metrics.SetLeader(false)
	}()
}

func (j *JobRunner) runOnLeader(ctx context.Context) {
	if !j.leader.IsLeader() {
		return
	}
	metrics.SetLeader(true)
	j.log.Info("became leader; starting background jobs")

	leaseTicker := time.NewTicker(j.cfg.JobLeaseCleanupInterval)
	crlTicker := time.NewTicker(j.cfg.JobCRLRefreshInterval)
	renewTicker := time.NewTicker(j.cfg.JobCertRenewInterval)
	kvRotTicker := time.NewTicker(j.cfg.JobKVRotationInterval)
	reencTicker := time.NewTicker(j.cfg.JobMasterKeyReencryptInterval)
	defer leaseTicker.Stop()
	defer crlTicker.Stop()
	defer renewTicker.Stop()
	defer kvRotTicker.Stop()
	defer reencTicker.Stop()

	if j.leader.IsLeader() {
		j.runLeaseCleanup(ctx)
		j.updateActiveLeasesMetric(ctx)
		j.runCRLRefresh(ctx)
		j.runCertRenewal(ctx)
		j.runKVRotation(ctx)
		j.runMasterKeyReencrypt(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			metrics.SetLeader(false)
			return
		case <-leaseTicker.C:
			if !j.leader.IsLeader() {
				continue
			}
			j.runLeaseCleanup(ctx)
			j.updateActiveLeasesMetric(ctx)
		case <-crlTicker.C:
			if !j.leader.IsLeader() {
				continue
			}
			j.runCRLRefresh(ctx)
		case <-renewTicker.C:
			if !j.leader.IsLeader() {
				continue
			}
			j.runCertRenewal(ctx)
		case <-kvRotTicker.C:
			if !j.leader.IsLeader() {
				continue
			}
			j.runKVRotation(ctx)
		case <-reencTicker.C:
			if !j.leader.IsLeader() {
				continue
			}
			j.runMasterKeyReencrypt(ctx)
		}
	}
}

func (j *JobRunner) runMasterKeyReencrypt(ctx context.Context) {
	if j.masterKey == nil {
		return
	}
	result, err := j.masterKey.ReencryptDEKs(ctx, 50)
	if err != nil {
		j.log.Warn("master key reencrypt failed", zap.Error(err))
		return
	}
	if result.CAs > 0 || result.Secrets > 0 {
		j.log.Info("master key reencrypt progress",
			zap.Int("cas", result.CAs),
			zap.Int("secrets", result.Secrets),
		)
	}
}

func (j *JobRunner) runKVRotation(ctx context.Context) {
	if j.rotation == nil {
		return
	}
	count, err := j.rotation.RunDue(ctx, time.Now().UTC())
	if err != nil {
		j.log.Warn("kv rotation failed", zap.Error(err))
		return
	}
	if count > 0 {
		j.log.Info("kv secrets rotated", zap.Int("count", count))
	}
}

func (j *JobRunner) runCertRenewal(ctx context.Context) {
	if j.pki == nil {
		return
	}
	count, err := j.pki.RenewExpiring(ctx, j.cfg.RenewGrace, 50)
	if err != nil {
		j.log.Warn("certificate renewal failed", zap.Error(err))
		return
	}
	if count > 0 {
		j.log.Info("certificates renewed", zap.Int("count", count))
	}
}

func (j *JobRunner) runLeaseCleanup(ctx context.Context) {
	if j.database == nil {
		return
	}
	revoked, err := j.database.CleanupExpired(ctx, 100)
	if err != nil {
		j.log.Warn("lease cleanup failed", zap.Error(err))
		return
	}
	if revoked > 0 {
		j.log.Info("expired leases revoked", zap.Int("count", revoked))
	}
}

func (j *JobRunner) updateActiveLeasesMetric(ctx context.Context) {
	if j.leases == nil {
		return
	}
	count, err := j.leases.CountActive(ctx)
	if err != nil {
		j.log.Warn("count active leases failed", zap.Error(err))
		return
	}
	metrics.SetActiveLeasesGauge(count)
}

func (j *JobRunner) runCRLRefresh(ctx context.Context) {
	if j.pki == nil || j.cas == nil {
		return
	}
	cas, err := j.cas.List(ctx)
	if err != nil {
		j.log.Warn("list cas for crl refresh failed", zap.Error(err))
		return
	}
	now := time.Now().UTC()
	for _, ca := range cas {
		if ca.Status != pki.CAStatusActive {
			continue
		}
		if ca.CRLNextUpdate != nil && ca.CRLNextUpdate.After(now) {
			continue
		}
		if _, err := j.pki.GenerateCRL(ctx, ca.ID); err != nil {
			j.log.Warn("crl refresh failed", zap.String("ca", ca.Name), zap.Error(err))
			continue
		}
		next := now.Add(24 * time.Hour)
		ca.CRLNextUpdate = &next
		if err := j.cas.Save(ctx, ca); err != nil {
			j.log.Warn("update crl_next_update failed", zap.String("ca", ca.Name), zap.Error(err))
		}
	}
}
