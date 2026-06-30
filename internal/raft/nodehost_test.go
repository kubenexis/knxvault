package raft_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/raft"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func startTestNode(t *testing.T, dir string, nodeID uint64, addr string, members map[uint64]string) *raft.NodeHostBundle {
	t.Helper()
	bundle, err := raft.StartNodeHost(config.RaftConfig{
		Enabled:        true,
		NodeID:         nodeID,
		RaftAddress:    addr,
		DataDir:        dir,
		InitialMembers: members,
		ElectionRTT:    10,
		HeartbeatRTT:   1,
		RTTMillisecond: 1,
	})
	if err != nil {
		t.Fatalf("StartNodeHost() = %v", err)
	}
	t.Cleanup(bundle.Stop)
	return bundle
}

func waitForLeader(t *testing.T, bundle *raft.NodeHostBundle) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if bundle.Ready() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("raft leader not elected")
}

func TestSingleNodeRaftPropose(t *testing.T) {
	dir := t.TempDir()
	addr := freePort(t)
	bundle := startTestNode(t, filepath.Join(dir, "n1"), 1, addr, nil)
	waitForLeader(t, bundle)

	ca := testRootCA("root")
	_, err := bundle.Client.Propose(context.Background(), raft.OpCASave, ca)
	if err != nil {
		t.Fatalf("Propose() = %v", err)
	}

	data, err := bundle.Client.Read(context.Background(), raft.OpCAGetByName, struct{ Name string }{Name: "root"})
	if err != nil {
		t.Fatalf("Read() = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected read response")
	}
}
