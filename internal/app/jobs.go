package app

import (
	"context"
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
	leader   leader.Elector
	database *service.DatabaseService
	pki      *service.PKIService
	cas      repository.CARepository
	cfg      config.Config
	log      *zap.Logger
}

// NewJobRunner constructs a background job runner.
func NewJobRunner(
	elector leader.Elector,
	database *service.DatabaseService,
	pki *service.PKIService,
	cas repository.CARepository,
	cfg config.Config,
	log *zap.Logger,
) *JobRunner {
	return &JobRunner{
		leader:   elector,
		database: database,
		pki:      pki,
		cas:      cas,
		cfg:      cfg,
		log:      log,
	}
}

// Start launches leader election and periodic jobs.
func (j *JobRunner) Start(ctx context.Context) {
	if j == nil || j.leader == nil {
		return
	}
	go func() {
		if err := j.leader.Run(ctx, j.runOnLeader); err != nil && ctx.Err() == nil {
			j.log.Warn("leader election stopped", zap.Error(err))
		}
	}()
}

func (j *JobRunner) runOnLeader(ctx context.Context) {
	metrics.SetLeader(j.leader.IsLeader())
	j.log.Info("became leader; starting background jobs")

	leaseTicker := time.NewTicker(j.cfg.JobLeaseCleanupInterval)
	crlTicker := time.NewTicker(j.cfg.JobCRLRefreshInterval)
	renewTicker := time.NewTicker(j.cfg.JobCertRenewInterval)
	defer leaseTicker.Stop()
	defer crlTicker.Stop()
	defer renewTicker.Stop()

	j.runLeaseCleanup(ctx)
	j.runCRLRefresh(ctx)
	j.runCertRenewal(ctx)

	for {
		select {
		case <-ctx.Done():
			metrics.SetLeader(false)
			return
		case <-leaseTicker.C:
			j.runLeaseCleanup(ctx)
		case <-crlTicker.C:
			j.runCRLRefresh(ctx)
		case <-renewTicker.C:
			j.runCertRenewal(ctx)
		}
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
	metrics.SetActiveLeasesGauge(revoked)
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
