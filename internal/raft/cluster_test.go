package raft_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/raft"
)

func TestParseInitialMembers(t *testing.T) {
	members, err := raft.ParseInitialMembers("1=127.0.0.1:63001,2=127.0.0.1:63002")
	if err != nil {
		t.Fatalf("ParseInitialMembers() = %v", err)
	}
	if members[1] != "127.0.0.1:63001" || members[2] != "127.0.0.1:63002" {
		t.Fatalf("members = %#v", members)
	}
}

func TestParseInitialMembersBootstrapErrors(t *testing.T) {
	if _, err := raft.ParseInitialMembers("bad-format"); err == nil {
		t.Fatal("expected invalid member format error")
	}
	if _, err := raft.ParseInitialMembers("x=host:63001"); err == nil {
		t.Fatal("expected invalid node id error")
	}
	if _, err := raft.ParseInitialMembers("1="); err == nil {
		t.Fatal("expected empty address error")
	}
	empty, err := raft.ParseInitialMembers("")
	if err != nil || empty != nil {
		t.Fatalf("empty bootstrap = %v, %v", empty, err)
	}
}

func TestParseInitialMembersQuorumBootstrap(t *testing.T) {
	members, err := raft.ParseInitialMembers("1=h1:63001,2=h2:63001,3=h3:63001")
	if err != nil {
		t.Fatalf("ParseInitialMembers() = %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("member count = %d, want 3 for quorum bootstrap", len(members))
	}
}
