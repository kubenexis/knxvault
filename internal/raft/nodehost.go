// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"fmt"
	"os"

	"github.com/lni/dragonboat/v3"
	dbconfig "github.com/lni/dragonboat/v3/config"
	sm "github.com/lni/dragonboat/v3/statemachine"

	appconfig "github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
)

// NodeHostBundle owns a running Dragonboat NodeHost and vault Raft client.
type NodeHostBundle struct {
	NodeHost *dragonboat.NodeHost
	Client   *Client
}

// StartNodeHost boots Dragonboat and joins or creates the vault Raft cluster.
func StartNodeHost(cfg appconfig.RaftConfig) (*NodeHostBundle, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create raft data dir: %w", err)
	}

	nhc := dbconfig.NodeHostConfig{
		NodeHostDir:       cfg.DataDir,
		RTTMillisecond:    cfg.RTTMillisecond,
		RaftAddress:       cfg.RaftAddress,
		ListenAddress:     cfg.ListenAddress,
		EnableMetrics:     true,
		RaftEventListener: eventListener{},
	}
	if cfg.MTLSCertFile != "" {
		nhc.MutualTLS = true
		nhc.CertFile = cfg.MTLSCertFile
		nhc.KeyFile = cfg.MTLSKeyFile
		nhc.CAFile = cfg.MTLSCAFile
		metrics.SetRaftTLSEnabled(true)
	} else {
		metrics.SetRaftTLSEnabled(false)
	}

	nh, err := dragonboat.NewNodeHost(nhc)
	if err != nil {
		return nil, fmt.Errorf("create nodehost: %w", err)
	}

	rc := dbconfig.Config{
		ClusterID:       DefaultClusterID,
		NodeID:          cfg.NodeID,
		ElectionRTT:     cfg.ElectionRTT,
		HeartbeatRTT:    cfg.HeartbeatRTT,
		CheckQuorum:     true,
		SnapshotEntries: 1000,
	}

	if !clusterRunning(nh) {
		members := toDragonboatTargets(cfg.InitialMembers)
		join := cfg.Join
		if len(members) == 0 {
			members = map[uint64]dragonboat.Target{
				cfg.NodeID: cfg.RaftAddress,
			}
		}
		if err := nh.StartCluster(members, join, CreateStateMachine, rc); err != nil {
			nh.Stop()
			return nil, fmt.Errorf("start raft cluster: %w", err)
		}
	}

	client := NewClient(nh, DefaultClusterID, cfg.NodeID)
	return &NodeHostBundle{NodeHost: nh, Client: client}, nil
}

// Ready reports whether the vault cluster has a known leader.
func (b *NodeHostBundle) Ready() bool {
	if b == nil || b.Client == nil {
		return false
	}
	_, valid, err := b.Client.LeaderID()
	return err == nil && valid
}

// Stop shuts down the NodeHost. Safe to call more than once.
func (b *NodeHostBundle) Stop() {
	if b == nil || b.NodeHost == nil {
		return
	}
	nh := b.NodeHost
	b.NodeHost = nil
	b.Client = nil
	nh.Stop()
}

func clusterRunning(nh *dragonboat.NodeHost) bool {
	_, _, err := nh.GetLeaderID(DefaultClusterID)
	return err != dragonboat.ErrClusterNotFound
}

func toDragonboatTargets(in map[uint64]string) map[uint64]dragonboat.Target {
	if len(in) == 0 {
		return nil
	}
	out := make(map[uint64]dragonboat.Target, len(in))
	for id, addr := range in {
		out[id] = addr
	}
	return out
}

// CreateStateMachine is re-exported for tests.
var _ sm.IStateMachine = (*VaultStateMachine)(nil)
