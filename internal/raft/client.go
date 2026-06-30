package raft

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lni/dragonboat/v3"
	"github.com/lni/dragonboat/v3/client"
)

const (
	// DefaultClusterID is the vault Raft cluster identifier.
	DefaultClusterID uint64 = 1
	defaultTimeout          = 10 * time.Second
)

// Client proposes commands and performs linearizable reads via NodeHost.
type Client struct {
	nh        *dragonboat.NodeHost
	clusterID uint64
	nodeID    uint64
	session   *client.Session
}

// NewClient constructs a Raft client around a running NodeHost.
func NewClient(nh *dragonboat.NodeHost, clusterID, nodeID uint64) *Client {
	return &Client{
		nh:        nh,
		clusterID: clusterID,
		nodeID:    nodeID,
		session:   nh.GetNoOPSession(clusterID),
	}
}

// NodeHost returns the underlying NodeHost.
func (c *Client) NodeHost() *dragonboat.NodeHost { return c.nh }

// ClusterID returns the vault cluster ID.
func (c *Client) ClusterID() uint64 { return c.clusterID }

// NodeID returns this node's Raft ID.
func (c *Client) NodeID() uint64 { return c.nodeID }

// Propose replicates a command and returns the encoded response.
func (c *Client) Propose(ctx context.Context, op string, payload any) ([]byte, error) {
	cmd, err := encodeCommand(op, payload)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	timeout, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	result, err := c.nh.SyncPropose(timeout, c.session, cmd)
	if err != nil {
		return nil, err
	}
	ObservePropose(time.Since(start), result.Value)
	if result.Data == nil {
		return nil, nil
	}
	return result.Data, nil
}

// Read performs a linearizable lookup.
func (c *Client) Read(ctx context.Context, op string, payload any) ([]byte, error) {
	query, err := encodeCommand(op, payload)
	if err != nil {
		return nil, err
	}
	var cmd Command
	if err := json.Unmarshal(query, &cmd); err != nil {
		return nil, err
	}
	timeout, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	val, err := c.nh.SyncRead(timeout, c.clusterID, cmd)
	if err != nil {
		return nil, err
	}
	switch out := val.(type) {
	case []byte:
		return out, nil
	default:
		return nil, fmt.Errorf("unexpected lookup result type %T", val)
	}
}

// IsLeader reports whether this node is the Raft leader.
func (c *Client) IsLeader() bool {
	leaderID, valid, err := c.nh.GetLeaderID(c.clusterID)
	if err != nil || !valid {
		return false
	}
	return leaderID == c.nodeID
}

// LeaderID returns the current leader node ID and whether leadership is known.
func (c *Client) LeaderID() (uint64, bool, error) {
	return c.nh.GetLeaderID(c.clusterID)
}

// RequestSnapshot triggers a Dragonboat snapshot.
func (c *Client) RequestSnapshot(ctx context.Context) error {
	timeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := c.nh.SyncRequestSnapshot(timeout, c.clusterID, dragonboat.DefaultSnapshotOption)
	return err
}

// Stop stops the NodeHost.
func (c *Client) Stop() {
	c.nh.Stop()
}
