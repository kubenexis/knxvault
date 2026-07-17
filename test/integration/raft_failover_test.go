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
	n2 := startRaftNode(t, base, 2, addr2, members)
	n3 := startRaftNode(t, base, 3, addr3, members)
	waitRaftReady(t, n1)

	path := "failover/app/config"
	sv := secrets.SecretVersion{
		ID:        uuid.New(),
		Path:      path,
		DataEnc:   []byte("cipher"),
		DEKEnc:    []byte("dek"),
		CreatedAt: time.Now().UTC(),
	}
	if _, err := n1.Client.Propose(context.Background(), raft.OpSecretPut, struct {
		SecretVersion secrets.SecretVersion
		CasVersion    *int
		MaxVersions   int
	}{SecretVersion: sv, MaxVersions: 10}); err != nil {
		t.Fatalf("initial propose: %v", err)
	}

	waitForSecret(t, n3.Client, path)

	n1.Stop()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if n2.Ready() || n3.Ready() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("cluster did not elect a new leader after stopping node 1")
}

func waitForSecret(t *testing.T, client *raft.Client, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := client.Read(context.Background(), raft.OpSecretGetLatest, struct{ Path string }{Path: path})
		if err == nil && len(data) > 0 {
			var sv secrets.SecretVersion
			if err := raft.DecodeResult(data, &sv); err == nil && sv.Path == path {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("secret %q not observed", path)
}
