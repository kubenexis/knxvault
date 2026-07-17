// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"context"
	"sync"
	"time"

	"github.com/kubenexis/knxvault/internal/infra/leader"
)

// raftLeaderProbe reports live Raft leadership (used by health and metrics).
type raftLeaderProbe interface {
	IsLeader() bool
}

// LeaderElector gates background jobs on Dragonboat leadership.
type LeaderElector struct {
	client raftLeaderProbe
	mu     sync.RWMutex
	leader bool
}

// NewLeaderElector constructs a Raft-backed leader elector.
func NewLeaderElector(client *Client) leader.Elector {
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
// Uses the live Dragonboat probe when available so /health leader matches knxvault_raft_leader.
func (e *LeaderElector) IsLeader() bool {
	if e.client != nil {
		return e.client.IsLeader()
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.leader
}

func (e *LeaderElector) setLeader(leader bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.leader = leader
}
