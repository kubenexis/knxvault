// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"strings"
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
	leader    leader.Elector
	monitor   *leader.Monitor
	database  *service.DatabaseService
	ssh       *service.SSHService
	pki       *service.PKIService
	rotation  *service.RotationService
	masterKey *service.MasterKeyService
	cas       repository.CARepository
	leases    repository.LeaseRepository
	cfg       config.Config
	log       *zap.Logger
}

// NewJobRunner constructs a background job runner.
func NewJobRunner(
	elector leader.Elector,
	monitor *leader.Monitor,
	database *service.DatabaseService,
	ssh *service.SSHService,
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
		monitor:   monitor,
		database:  database,
		ssh:       ssh,
		pki:       pki,
		rotation:  rotation,
		masterKey: masterKey,
		cas:       cas,
		leases:    leases,
		cfg:       cfg,
		log:       log,
	}
}

// Start launches leader election and periodic jobs.
func (j *JobRunner) Start(ctx context.Context) {
	if j == nil || j.leader == nil {
		return
	}
	if j.monitor != nil {
		j.monitor.Activate()
		j.monitor.SetRunning(true)
	}
	metrics.SetLeaderElectionRunning(true)
	go func() {
		defer func() {
			if j.monitor != nil {
				j.monitor.SetRunning(false)
			}
			metrics.SetLeaderElectionRunning(false)
			metrics.SetLeader(false)
		}()
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
	kvRotTicker := time.NewTicker(j.cfg.JobKVRotationInterval)
	reencTicker := time.NewTicker(j.cfg.JobMasterKeyReencryptInterval)
	defer leaseTicker.Stop()
	defer crlTicker.Stop()
	defer renewTicker.Stop()
	defer kvRotTicker.Stop()
	defer reencTicker.Stop()

	j.runLeaseCleanup(ctx)
	j.updateActiveLeasesMetric(ctx)
	j.runCRLRefresh(ctx)
	j.runCertRenewal(ctx)
	j.runLeaseRenewal(ctx)
	j.runKVRotation(ctx)
	j.runMasterKeyReencrypt(ctx)

	for {
		select {
		case <-ctx.Done():
			metrics.SetLeader(false)
			return
		case <-leaseTicker.C:
			j.runLeaseCleanup(ctx)
			j.updateActiveLeasesMetric(ctx)
		case <-crlTicker.C:
			j.runCRLRefresh(ctx)
		case <-renewTicker.C:
			j.runCertRenewal(ctx)
			j.runLeaseRenewal(ctx)
		case <-kvRotTicker.C:
			j.runKVRotation(ctx)
		case <-reencTicker.C:
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

func (j *JobRunner) runLeaseRenewal(ctx context.Context) {
	grace := leaseRenewGrace(j.cfg.RenewGrace)
	if j.database != nil {
		count, err := j.database.RenewExpiring(ctx, grace, 50)
		if err != nil {
			j.log.Warn("database lease renewal failed", zap.Error(err))
		} else if count > 0 {
			j.log.Info("database leases renewed", zap.Int("count", count))
		}
	}
	if j.ssh != nil {
		count, err := j.ssh.RenewExpiring(ctx, grace, 50)
		if err != nil {
			j.log.Warn("ssh lease renewal failed", zap.Error(err))
		} else if count > 0 {
			j.log.Info("ssh leases renewed", zap.Int("count", count))
		}
	}
}

// leaseRenewGrace picks DB/SSH lease renewal window (capped at 24h; PKI uses RenewGrace separately).
func leaseRenewGrace(pkiRenewGrace time.Duration) time.Duration {
	const defaultLeaseGrace = 24 * time.Hour
	if pkiRenewGrace <= 0 {
		return defaultLeaseGrace
	}
	if pkiRenewGrace > defaultLeaseGrace {
		return defaultLeaseGrace
	}
	return pkiRenewGrace
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
	revoked := 0
	if j.database != nil {
		count, err := j.database.CleanupExpired(ctx, 100)
		if err != nil {
			j.log.Warn("database lease cleanup failed", zap.Error(err))
		} else {
			revoked += count
		}
	}
	if j.ssh != nil {
		count, err := j.ssh.CleanupExpired(ctx, 100)
		if err != nil {
			j.log.Warn("ssh lease cleanup failed", zap.Error(err))
		} else {
			revoked += count
		}
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
	leases, err := j.leases.List(ctx)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	byKey := make(map[string]int)
	for _, l := range leases {
		if !l.Active(now) {
			continue
		}
		key := l.Engine + "\x00" + l.RoleName
		byKey[key]++
	}
	for key, n := range byKey {
		parts := strings.SplitN(key, "\x00", 2)
		metrics.SetLeasesByEngine(parts[0], parts[1], n)
	}
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
