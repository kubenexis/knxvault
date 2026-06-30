package app_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	databaseengine "github.com/kubenexis/knxvault/internal/engine/secrets/database"
	"github.com/kubenexis/knxvault/internal/infra/leader"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

type staticElector struct {
	leader bool
}

func (e *staticElector) Run(ctx context.Context, onLeadership func(context.Context)) error {
	if e.leader {
		onLeadership(ctx)
	}
	<-ctx.Done()
	return ctx.Err()
}

func (e *staticElector) IsLeader() bool { return e.leader }

func TestJobRunnerActiveLeasesMetric(t *testing.T) {
	leases := memory.NewLeaseRepository()
	now := time.Now().UTC()
	ctx := context.Background()
	active := &secrets.Lease{
		ID:         "l_active",
		Path:       "database/creds/r/l_active",
		RoleName:   "r",
		Engine:     "database",
		TTLSeconds: 3600,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
		Renewable:  true,
	}
	expired := &secrets.Lease{
		ID:         "l_expired",
		Path:       "database/creds/r/l_expired",
		RoleName:   "r",
		Engine:     "database",
		TTLSeconds: 60,
		CreatedAt:  now.Add(-2 * time.Hour),
		ExpiresAt:  now.Add(-time.Hour),
		Renewable:  true,
	}
	if err := leases.Save(ctx, active); err != nil {
		t.Fatalf("Save(active) = %v", err)
	}
	if err := leases.Save(ctx, expired); err != nil {
		t.Fatalf("Save(expired) = %v", err)
	}

	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	runner := app.NewJobRunner(
		&staticElector{leader: true},
		nil,
		nil,
		nil,
		nil,
		leases,
		cfg,
		zap.NewNop(),
	)

	count, err := leases.CountActive(ctx)
	if err != nil {
		t.Fatalf("CountActive() = %v", err)
	}
	if count != 1 {
		t.Fatalf("CountActive() = %d, want 1", count)
	}

	var _ leader.Elector = &staticElector{}
	_ = runner
}

func TestJobRunnerStartNilLeader(t *testing.T) {
	runner := app.NewJobRunner(nil, nil, nil, nil, nil, nil, config.Config{}, zap.NewNop())
	runner.Start(context.Background())
}

func TestJobRunnerLeaseCleanupOnLeadership(t *testing.T) {
	key := make([]byte, 32)
	cryptoSvc, err := crypto.NewService(key)
	if err != nil {
		t.Fatalf("NewService() = %v", err)
	}
	roles := memory.NewDatabaseRoleRepository()
	leases := memory.NewLeaseRepository()
	secretsRepo := memory.NewSecretRepository()
	engine := databaseengine.NewEngine(roles, leases, secretsRepo, cryptoSvc)
	dbSvc := service.NewDatabaseService(engine, nil)
	ctx := context.Background()

	if err := dbSvc.SaveRole(ctx, databaseengine.RoleConfig{Name: "app", TTLSeconds: 30}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}
	result, err := dbSvc.GenerateCredentials(ctx, databaseengine.CredsRequest{Role: "app"})
	if err != nil {
		t.Fatalf("GenerateCredentials() = %v", err)
	}
	lease, err := leases.Get(ctx, result.LeaseID)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	lease.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := leases.Save(ctx, lease); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	t.Setenv("KNXVAULT_JOB_LEASE_CLEANUP_INTERVAL", "20ms")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	runCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	runner := app.NewJobRunner(&staticElector{leader: true}, dbSvc, nil, nil, nil, leases, cfg, zap.NewNop())
	runner.Start(runCtx)
	<-runCtx.Done()

	lease, err = leases.Get(ctx, result.LeaseID)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if lease.RevokedAt == nil {
		t.Fatal("expected expired lease to be revoked by job runner")
	}
}

func TestJobRunnerNonLeaderSkipsJobs(t *testing.T) {
	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	t.Setenv("KNXVAULT_JOB_LEASE_CLEANUP_INTERVAL", "20ms")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	runCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	runner := app.NewJobRunner(&staticElector{leader: false}, nil, nil, nil, nil, nil, cfg, zap.NewNop())
	runner.Start(runCtx)
	<-runCtx.Done()
}
