package raft_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/raft"
)

type fakeRaftClient struct {
	leader bool
}

func (f *fakeRaftClient) IsLeader() bool { return f.leader }

func TestLeaderElectorTracksClientRole(t *testing.T) {
	t.Parallel()

	client := &fakeRaftClient{leader: true}
	elector := raft.NewLeaderElector(client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	led := make(chan struct{}, 1)
	go func() {
		_ = elector.Run(ctx, func(context.Context) {
			led <- struct{}{}
		})
	}()

	select {
	case <-led:
	case <-time.After(2 * time.Second):
		t.Fatal("expected leadership callback")
	}
	if !elector.IsLeader() {
		t.Fatal("expected elector to report leader")
	}

	client.leader = false
	select {
	case <-led:
		t.Fatal("unexpected second leadership signal")
	case <-time.After(1500 * time.Millisecond):
	}
	if elector.IsLeader() {
		t.Fatal("expected elector to clear leader after step-down")
	}
}