// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	raftLeaderGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "knxvault_raft_leader",
			Help: "1 when this node is the Raft leader, 0 otherwise",
		},
	)
	raftTermGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "knxvault_raft_term",
			Help: "Current Raft term for the vault cluster",
		},
	)
	raftCommitIndexGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "knxvault_raft_commit_index",
			Help: "Committed Raft log index for the vault cluster",
		},
	)
	raftProposeDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "knxvault_raft_propose_duration_seconds",
			Help:    "Vault Raft command propose latency",
			Buckets: prometheus.DefBuckets,
		},
	)
)

// ObservePropose records propose latency and the applied index when available.
func ObservePropose(d time.Duration, index uint64) {
	raftProposeDuration.Observe(d.Seconds())
	if index > 0 {
		raftCommitIndexGauge.Set(float64(index))
	}
}

// SetRaftLeader records whether this node is the Raft leader.
func SetRaftLeader(isLeader bool) {
	if isLeader {
		raftLeaderGauge.Set(1)
	} else {
		raftLeaderGauge.Set(0)
	}
}
