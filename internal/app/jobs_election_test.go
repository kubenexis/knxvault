package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/infra/leader"
)

type failingElector struct{}

func (f *failingElector) Run(context.Context, func(context.Context)) error {
	return errors.New("election failed")
}

func (f *failingElector) IsLeader() bool { return false }

func TestJobRunnerElectionMonitorStopsOnFailure(t *testing.T) {
	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	monitor := leader.NewMonitor()
	runner := app.NewJobRunner(&failingElector{}, monitor, nil, nil, nil, nil, nil, nil, cfg, zap.NewNop())
	runner.Start(context.Background())

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !monitor.Running() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected leader election monitor to stop after failure")
}
