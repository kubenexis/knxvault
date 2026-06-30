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
