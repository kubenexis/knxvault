package raft

import "testing"

type stubLeaderProbe struct {
	leader bool
}

func (s *stubLeaderProbe) IsLeader() bool { return s.leader }

func TestLeaderElectorIsLeaderUsesLiveProbe(t *testing.T) {
	probe := &stubLeaderProbe{leader: false}
	e := &LeaderElector{client: probe}
	e.setLeader(true)
	if e.IsLeader() {
		t.Fatal("expected live probe to override cached leadership")
	}
	probe.leader = true
	if !e.IsLeader() {
		t.Fatal("expected live probe true")
	}
}

func TestLeaderElectorIsLeaderWithoutClient(t *testing.T) {
	e := &LeaderElector{}
	if e.IsLeader() {
		t.Fatal("expected false without client or cache")
	}
	e.setLeader(true)
	if !e.IsLeader() {
		t.Fatal("expected cached leadership when client absent")
	}
}
