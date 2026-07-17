// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/raft"
)

func TestIntegrationRaftLeaderFailover(t *testing.T) {
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
		safeStopRaft(n1)
	})

	waitRaftQuorumReady(t, n1, n2, n3)
	nodes := []*raft.NodeHostBundle{n1, n2, n3}

	path := "failover/app/config"
	sv := secrets.SecretVersion{
		ID:        uuid.New(),
		Path:      path,
		DataEnc:   []byte("cipher"),
		DEKEnc:    []byte("dek"),
		CreatedAt: time.Now().UTC(),
	}
	proposeOnLeader(t, nodes, raft.OpSecretPut, struct {
		SecretVersion secrets.SecretVersion
		CasVersion    *int
		MaxVersions   int
	}{SecretVersion: sv, MaxVersions: 10})

	waitForSecret(t, n3.Client, path)

	// Stop the *current* leader (not always n1).
	leader := waitRaftLeader(t, testRaftReadyTimeout, nodes...)
	safeStopRaft(leader)

	survivors := make([]*raft.NodeHostBundle, 0, 2)
	for _, n := range nodes {
		if n != leader && n != nil && n.Client != nil {
			survivors = append(survivors, n)
		}
	}
	// Require a real leader election among survivors (not merely Ready()).
	_ = waitRaftLeader(t, testRaftFailoverWait, survivors...)
}

func waitForSecret(t *testing.T, client *raft.Client, path string) {
	t.Helper()
	if client == nil {
		t.Fatal("nil raft client")
	}
	deadline := time.Now().Add(testRaftReplicateWait)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		data, err := client.Read(ctx, raft.OpSecretGetLatest, struct{ Path string }{Path: path})
		cancel()
		if err == nil && len(data) > 0 {
			var sv secrets.SecretVersion
			if err := raft.DecodeResult(data, &sv); err == nil && sv.Path == path {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("secret %q not observed", path)
}
