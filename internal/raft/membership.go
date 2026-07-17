// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package raft

import (
	"context"
	"fmt"
	"time"
)

const membershipTimeout = 30 * time.Second

// AddNode requests adding a new voting member to the cluster.
func (c *Client) AddNode(ctx context.Context, nodeID uint64, address string) error {
	if c == nil || c.nh == nil {
		return fmt.Errorf("raft client not configured")
	}
	if nodeID == 0 {
		return fmt.Errorf("node id must be > 0")
	}
	if address == "" {
		return fmt.Errorf("raft address is required")
	}
	timeout, cancel := context.WithTimeout(ctx, membershipTimeout)
	defer cancel()
	return c.nh.SyncRequestAddNode(timeout, c.clusterID, nodeID, address, 0)
}

// RemoveNode requests removal of a voting member from the cluster.
func (c *Client) RemoveNode(ctx context.Context, nodeID uint64) error {
	if nodeID == 0 {
		return fmt.Errorf("node id must be > 0")
	}
	if c != nil && nodeID == c.nodeID {
		return fmt.Errorf("cannot remove local raft node; shut down the process instead")
	}
	if c == nil || c.nh == nil {
		return fmt.Errorf("raft client not configured")
	}
	timeout, cancel := context.WithTimeout(ctx, membershipTimeout)
	defer cancel()
	return c.nh.SyncRequestDeleteNode(timeout, c.clusterID, nodeID, 0)
}
