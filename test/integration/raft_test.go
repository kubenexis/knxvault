package integration_test

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/raft"
)

func raftFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func startRaftNode(t *testing.T, base string, nodeID uint64, addr string, members map[uint64]string) *raft.NodeHostBundle {
	t.Helper()
	bundle := startRaftNodeManual(t, base, nodeID, addr, members)
	t.Cleanup(bundle.Stop)
	return bundle
}

func startRaftNodeManual(t *testing.T, base string, nodeID uint64, addr string, members map[uint64]string) *raft.NodeHostBundle {
	t.Helper()
	bundle, err := raft.StartNodeHost(config.RaftConfig{
		Enabled:        true,
		NodeID:         nodeID,
		RaftAddress:    addr,
		DataDir:        filepath.Join(base, "node-"+strconv.FormatUint(nodeID, 10)),
		InitialMembers: members,
		ElectionRTT:    10,
		HeartbeatRTT:   1,
		RTTMillisecond: 1,
	})
	if err != nil {
		t.Fatalf("StartNodeHost(%d) = %v", nodeID, err)
	}
	return bundle
}

func waitRaftReady(t *testing.T, bundle *raft.NodeHostBundle) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if bundle.Ready() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("raft cluster not ready")
}

func TestIntegrationRaftThreeNodeCluster(t *testing.T) {
	base := t.TempDir()
	addr1 := raftFreePort(t)
	addr2 := raftFreePort(t)
	addr3 := raftFreePort(t)
	members := map[uint64]string{
		1: addr1,
		2: addr2,
		3: addr3,
	}

	n1 := startRaftNode(t, base, 1, addr1, members)
	n2 := startRaftNode(t, base, 2, addr2, members)
	n3 := startRaftNode(t, base, 3, addr3, members)

	waitRaftReady(t, n1)
	waitRaftReady(t, n2)
	waitRaftReady(t, n3)

	ca := &pki.CA{
		ID:            uuid.New(),
		Name:          "raft-root",
		Type:          pki.CATypeRoot,
		Serial:        "01",
		CertPEM:       "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		PrivateKeyEnc: []byte{1, 2, 3},
		DEKEnc:        []byte{4, 5, 6},
		Status:        pki.CAStatusActive,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour),
	}
	if _, err := n1.Client.Propose(context.Background(), raft.OpCASave, ca); err != nil {
		t.Fatalf("propose on leader candidate: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := n3.Client.Read(context.Background(), raft.OpCAGetByName, struct{ Name string }{Name: "raft-root"})
		if err == nil && len(data) > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("follower did not observe replicated CA")
}
