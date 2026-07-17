// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lni/dragonboat/v3/logger"

	"github.com/kubenexis/knxvault/internal/config"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/raft"
)

// Integration Raft timing: defaults (ElectionRTT=10, RTT=1ms) are too aggressive under
// loaded CI hosts and cause election thrash + connection-refused noise. These values keep
// tests fast while remaining stable (election ≈ 200–400ms, heartbeat ≈ 20ms).
const (
	testRaftElectionRTT    uint64 = 20
	testRaftHeartbeatRTT   uint64 = 2
	testRaftRTTMillisecond uint64 = 10

	testRaftReadyTimeout   = 30 * time.Second
	testRaftReplicateWait  = 20 * time.Second
	testRaftFailoverWait   = 45 * time.Second
	testRaftProposeTimeout = 15 * time.Second
	testRaftPortAllocTries = 8
)

var quietDragonboatOnce sync.Once

func quietDragonboatLogs() {
	quietDragonboatOnce.Do(func() {
		for _, name := range []string{
			"raft", "rsm", "transport", "dragonboat", "logdb", "config", "gossip",
		} {
			logger.GetLogger(name).SetLevel(logger.ERROR)
		}
	})
}

func raftFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	// Brief settle so the kernel releases the port for Dragonboat bind.
	time.Sleep(5 * time.Millisecond)
	return addr
}

func startRaftNode(t *testing.T, base string, nodeID uint64, addr string, members map[uint64]string) *raft.NodeHostBundle {
	t.Helper()
	bundle := startRaftNodeManual(t, base, nodeID, addr, members)
	t.Cleanup(func() { safeStopRaft(bundle) })
	return bundle
}

func startRaftNodeManual(t *testing.T, base string, nodeID uint64, addr string, members map[uint64]string) *raft.NodeHostBundle {
	t.Helper()
	quietDragonboatLogs()

	// Retry bind: raftFreePort has a small TOCTOU window under parallel packages/tests.
	var lastErr error
	tryAddr := addr
	for attempt := 0; attempt < testRaftPortAllocTries; attempt++ {
		if attempt > 0 {
			tryAddr = raftFreePort(t)
			// Keep InitialMembers in sync when this node's advertised address changes.
			if members != nil {
				members[nodeID] = tryAddr
			}
		}
		bundle, err := raft.StartNodeHost(config.RaftConfig{
			Enabled:        true,
			NodeID:         nodeID,
			RaftAddress:    tryAddr,
			DataDir:        filepath.Join(base, "node-"+strconv.FormatUint(nodeID, 10)),
			InitialMembers: members,
			ElectionRTT:    testRaftElectionRTT,
			HeartbeatRTT:   testRaftHeartbeatRTT,
			RTTMillisecond: testRaftRTTMillisecond,
		})
		if err == nil {
			return bundle
		}
		lastErr = err
		time.Sleep(time.Duration(20*(attempt+1)) * time.Millisecond)
	}
	t.Fatalf("StartNodeHost(%d) after %d tries: %v", nodeID, testRaftPortAllocTries, lastErr)
	return nil
}

func safeStopRaft(b *raft.NodeHostBundle) {
	if b == nil {
		return
	}
	// Swallow panics from double-stop races in dragonboat during test cleanup.
	defer func() { _ = recover() }()
	b.Stop()
}

// waitRaftReady waits until the cluster has a known leader (any node).
func waitRaftReady(t *testing.T, bundle *raft.NodeHostBundle) {
	t.Helper()
	deadline := time.Now().Add(testRaftReadyTimeout)
	for time.Now().Before(deadline) {
		if bundle != nil && bundle.Ready() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("raft cluster not ready (no known leader)")
}

// waitRaftQuorumReady waits until every live node sees a known leader.
func waitRaftQuorumReady(t *testing.T, nodes ...*raft.NodeHostBundle) {
	t.Helper()
	deadline := time.Now().Add(testRaftReadyTimeout)
	for time.Now().Before(deadline) {
		all := true
		for _, n := range nodes {
			if n == nil || !n.Ready() {
				all = false
				break
			}
		}
		if all {
			// Brief stability window: leader id should stay valid for two polls.
			time.Sleep(50 * time.Millisecond)
			stable := true
			for _, n := range nodes {
				if n == nil || !n.Ready() {
					stable = false
					break
				}
			}
			if stable {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("raft quorum not ready")
}

// waitRaftLeader returns a node that is the current leader among the set.
func waitRaftLeader(t *testing.T, timeout time.Duration, nodes ...*raft.NodeHostBundle) *raft.NodeHostBundle {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			if n == nil || n.Client == nil {
				continue
			}
			if n.Client.IsLeader() {
				return n
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no raft leader elected within timeout")
	return nil
}

// proposeOnLeader proposes via the current leader, retrying if leadership moves.
func proposeOnLeader(t *testing.T, nodes []*raft.NodeHostBundle, op string, payload any) {
	t.Helper()
	deadline := time.Now().Add(testRaftProposeTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		leader := findLeader(nodes)
		if leader == nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := leader.Client.Propose(ctx, op, payload)
		cancel()
		if err == nil {
			return
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("propose %s: %v", op, lastErr)
}

func findLeader(nodes []*raft.NodeHostBundle) *raft.NodeHostBundle {
	for _, n := range nodes {
		if n != nil && n.Client != nil && n.Client.IsLeader() {
			return n
		}
	}
	return nil
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

	// Stagger starts slightly to reduce first-election stampede.
	n1 := startRaftNode(t, base, 1, addr1, members)
	time.Sleep(20 * time.Millisecond)
	n2 := startRaftNode(t, base, 2, addr2, members)
	time.Sleep(20 * time.Millisecond)
	n3 := startRaftNode(t, base, 3, addr3, members)

	waitRaftQuorumReady(t, n1, n2, n3)
	_ = waitRaftLeader(t, testRaftReadyTimeout, n1, n2, n3)

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
	proposeOnLeader(t, []*raft.NodeHostBundle{n1, n2, n3}, raft.OpCASave, ca)

	deadline := time.Now().Add(testRaftReplicateWait)
	for time.Now().Before(deadline) {
		data, err := n3.Client.Read(context.Background(), raft.OpCAGetByName, struct{ Name string }{Name: "raft-root"})
		if err == nil && len(data) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("follower did not observe replicated CA")
}

func TestRaftLeaderFailover(t *testing.T) {
	base := t.TempDir()
	addr1 := raftFreePort(t)
	addr2 := raftFreePort(t)
	addr3 := raftFreePort(t)
	members := map[uint64]string{1: addr1, 2: addr2, 3: addr3}

	n1 := startRaftNodeManual(t, base, 1, addr1, members)
	time.Sleep(20 * time.Millisecond)
	n2 := startRaftNode(t, base, 2, addr2, members)
	time.Sleep(20 * time.Millisecond)
	n3 := startRaftNode(t, base, 3, addr3, members)
	t.Cleanup(func() {
		safeStopRaft(n2)
		safeStopRaft(n3)
		// n1 may already be stopped mid-test.
		safeStopRaft(n1)
	})

	waitRaftQuorumReady(t, n1, n2, n3)

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

	nodes := []*raft.NodeHostBundle{n1, n2, n3}
	proposeOnLeader(t, nodes, raft.OpSecretPut, secretPayload)

	leader := waitRaftLeader(t, testRaftReadyTimeout, nodes...)
	leaderID, valid, err := leader.Client.LeaderID()
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
	safeStopRaft(stopped)

	// Wait for a *new* leader among remaining nodes (Ready alone is not enough).
	survivors := make([]*raft.NodeHostBundle, 0, 2)
	for _, n := range nodes {
		if n != stopped {
			survivors = append(survivors, n)
		}
	}
	newLeader := waitRaftLeader(t, testRaftFailoverWait, survivors...)

	afterPayload := secretPayload
	afterPayload.SecretVersion.ID = uuid.New()
	afterPayload.SecretVersion.Path = "failover/after"
	proposeCtx, cancel := context.WithTimeout(context.Background(), testRaftProposeTimeout)
	defer cancel()
	if _, err := newLeader.Client.Propose(proposeCtx, raft.OpSecretPut, afterPayload); err != nil {
		// Leadership may have moved once more; retry via helper.
		proposeOnLeader(t, survivors, raft.OpSecretPut, afterPayload)
	}

	for _, node := range survivors {
		if node == nil || node.Client == nil {
			continue
		}
		readDeadline := time.Now().Add(testRaftReplicateWait)
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
			time.Sleep(50 * time.Millisecond)
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
	time.Sleep(20 * time.Millisecond)
	n2 := startRaftNode(t, base, 2, addr2, members)
	time.Sleep(20 * time.Millisecond)
	n3 := startRaftNode(t, base, 3, addr3, members)
	waitRaftQuorumReady(t, n1, n2, n3)
	nodes := []*raft.NodeHostBundle{n1, n2, n3}

	entry := struct {
		Actor    string
		Action   string
		Resource string
		Status   string
	}{Actor: "admin", Action: "kv.read", Resource: "app/db", Status: "success"}
	// Snapshot must run on leader; propose first then snapshot from leader.
	proposeOnLeader(t, nodes, raft.OpAuditAppend, entry)
	leader := waitRaftLeader(t, testRaftReadyTimeout, nodes...)
	if err := leader.Client.RequestSnapshot(context.Background()); err != nil {
		t.Fatalf("RequestSnapshot: %v", err)
	}

	deadline := time.Now().Add(testRaftReplicateWait)
	for time.Now().Before(deadline) {
		data, err := n3.Client.Read(context.Background(), raft.OpAuditList, struct {
			Limit    int
			OrderAsc bool
		}{Limit: 10, OrderAsc: true})
		if err == nil && len(data) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("follower did not observe audit after snapshot")
}
