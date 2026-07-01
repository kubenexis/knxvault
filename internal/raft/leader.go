package raft

import (
	"context"
	"sync"
	"time"

	"github.com/kubenexis/knxvault/internal/infra/leader"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
)

type leaderClient interface {
	IsLeader() bool
}

// LeaderElector gates background jobs on Dragonboat leadership.
type LeaderElector struct {
	client leaderClient
	mu     sync.RWMutex
	leader bool
}

// NewLeaderElector constructs a Raft-backed leader elector.
func NewLeaderElector(client leaderClient) leader.Elector {
	return &LeaderElector{client: client}
}

// Run watches Raft leadership and invokes onLeadership on the leader node.
func (e *LeaderElector) Run(ctx context.Context, onLeadership func(ctx context.Context)) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var leadCancel context.CancelFunc
	for {
		select {
		case <-ctx.Done():
			if leadCancel != nil {
				leadCancel()
			}
			e.setLeader(false)
			SetRaftLeader(false)
			return ctx.Err()
		case <-ticker.C:
			isLeader := e.client != nil && e.client.IsLeader()
			SetRaftLeader(isLeader)
			metrics.SetLeader(isLeader)
			if isLeader {
				if leadCancel == nil {
					var leadCtx context.Context
					leadCtx, leadCancel = context.WithCancel(ctx)
					e.setLeader(true)
					go onLeadership(leadCtx)
				}
				continue
			}
			if leadCancel != nil {
				leadCancel()
				leadCancel = nil
			}
			e.setLeader(false)
		}
	}
}

// IsLeader reports whether this node is the Raft leader.
func (e *LeaderElector) IsLeader() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.leader
}

func (e *LeaderElector) setLeader(leader bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.leader = leader
}
