// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"github.com/lni/dragonboat/v3/raftio"
)

type eventListener struct{}

func (eventListener) LeaderUpdated(info raftio.LeaderInfo) {
	if info.ClusterID != DefaultClusterID {
		return
	}
	raftTermGauge.Set(float64(info.Term))
	SetRaftLeader(info.LeaderID == info.NodeID && info.LeaderID != raftio.NoLeader)
}
