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
	"github.com/kubenexis/knxvault/internal/domain/secrets"
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

func TestRaftLeaderFailover(t *testing.T) {
	// Timeouts: election RTT=10, heartbeat RTT=1, RTT ms=1 → expect new leader < 10s.
	// Allow 30s ceiling per backlog acceptance criteria.
	const failoverWait = 30 * time.Second

	base := t.TempDir()
	addr1 := raftFreePort(t)
	addr2 := raftFreePort(t)
	addr3 := raftFreePort(t)
	members := map[uint64]string{1: addr1, 2: addr2, 3: addr3}

	n1 := startRaftNodeManual(t, base, 1, addr1, members)
	n2 := startRaftNode(t, base, 2, addr2, members)
	n3 := startRaftNode(t, base, 3, addr3, members)
	waitRaftReady(t, n1)
	waitRaftReady(t, n2)
	waitRaftReady(t, n3)

	secretPath := "failover/app"
	secretPayload := struct {
		SecretVersion secrets.SecretVersion
		CasVersion    *int
		MaxVersions   int
	}{
		SecretVersion: secrets.SecretVersion{
			ID:        uuid.New(),
			Path:      secretPath,
			DataEnc:   []byte{1, 2, 3},
			DEKEnc:    []byte{4, 5, 6},
			CreatedAt: time.Now().UTC(),
		},
		MaxVersions: 10,
	}

	if _, err := n1.Client.Propose(context.Background(), raft.OpSecretPut, secretPayload); err != nil {
		t.Fatalf("initial write: %v", err)
	}

	leaderID, valid, err := n1.Client.LeaderID()
	if err != nil || !valid {
		t.Fatalf("leader before failover: %v valid=%v", err, valid)
	}
	var stopped *raft.NodeHostBundle
	switch leaderID {
	case 1:
		stopped = n1
	case 2:
		stopped = n2
	case 3:
		stopped = n3
	default:
		t.Fatalf("unexpected leader %d", leaderID)
	}
	stopped.Stop()

	deadline := time.Now().Add(failoverWait)
	var leader *raft.NodeHostBundle
	for time.Now().Before(deadline) {
		for _, node := range []*raft.NodeHostBundle{n1, n2, n3} {
			if node == stopped || !node.Ready() {
				continue
			}
			if node.Client.IsLeader() {
				leader = node
				break
			}
		}
		if leader != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if leader == nil {
		t.Fatal("quorum did not elect a new leader within failover window")
	}

	afterPayload := secretPayload
	afterPayload.SecretVersion.ID = uuid.New()
	afterPayload.SecretVersion.Path = "failover/after"
	proposeCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := leader.Client.Propose(proposeCtx, raft.OpSecretPut, afterPayload); err != nil {
		t.Fatalf("write after failover: %v", err)
	}

	for _, node := range []*raft.NodeHostBundle{n1, n2, n3} {
		if node == stopped {
			continue
		}
		readDeadline := time.Now().Add(5 * time.Second)
		var ok bool
		for time.Now().Before(readDeadline) {
			data, err := node.Client.Read(context.Background(), raft.OpSecretGetLatest, struct{ Path string }{Path: secretPath})
			if err == nil && len(data) > 0 {
				var sv secrets.SecretVersion
				if raft.DecodeResult(data, &sv) == nil && sv.Path == secretPath {
					ok = true
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ok {
			t.Fatalf("node %d did not observe secret after failover", node.Client.NodeID())
		}
	}
}

func TestIntegrationRaftSnapshotPreservesAudit(t *testing.T) {
	base := t.TempDir()
	addr1 := raftFreePort(t)
	addr2 := raftFreePort(t)
	addr3 := raftFreePort(t)
	members := map[uint64]string{1: addr1, 2: addr2, 3: addr3}

	n1 := startRaftNode(t, base, 1, addr1, members)
	_ = startRaftNode(t, base, 2, addr2, members)
	n3 := startRaftNode(t, base, 3, addr3, members)
	waitRaftReady(t, n1)

	entry := struct {
		Actor    string
		Action   string
		Resource string
		Status   string
	}{Actor: "admin", Action: "kv.read", Resource: "app/db", Status: "success"}
	if _, err := n1.Client.Propose(context.Background(), raft.OpAuditAppend, entry); err != nil {
		t.Fatalf("audit append: %v", err)
	}
	if err := n1.Client.RequestSnapshot(context.Background()); err != nil {
		t.Fatalf("RequestSnapshot: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := n3.Client.Read(context.Background(), raft.OpAuditList, struct {
			Limit    int
			OrderAsc bool
		}{Limit: 10, OrderAsc: true})
		if err == nil && len(data) > 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("follower did not observe audit after snapshot")
}
