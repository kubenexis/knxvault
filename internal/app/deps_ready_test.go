// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/infra/leader"
)

type staticElectorForReady struct {
	leader bool
}

func (e *staticElectorForReady) Run(ctx context.Context, onLeadership func(context.Context)) error {
	if e.leader {
		onLeadership(ctx)
	}
	<-ctx.Done()
	return ctx.Err()
}

func (e *staticElectorForReady) IsLeader() bool { return e.leader }

func TestReadyRequiresLeaderElectionLoop(t *testing.T) {
	cfg := config.Config{HAEnabled: true}
	monitor := leader.NewMonitor()
	deps := &Dependencies{cfg: cfg, LeaderMonitor: monitor}

	if err := deps.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() before JobRunner.Start() = %v", err)
	}

	runner := NewJobRunner(&staticElectorForReady{leader: false}, monitor, nil, nil, nil, nil, nil, nil, nil, cfg, zap.NewNop())
	runner.Start(context.Background())

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if monitor.Running() {
			if err := deps.Ready(context.Background()); err != nil {
				t.Fatalf("Ready() = %v while election running", err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("election monitor never started")
}
