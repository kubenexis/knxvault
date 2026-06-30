package raft_test

import (
	"bytes"
	"testing"

	"github.com/kubenexis/knxvault/internal/raft"
)

func TestVaultStateMachineSnapshotPreservesAudit(t *testing.T) {
	sm := raft.NewVaultStateMachine()
	entry := struct {
		Actor    string
		Action   string
		Resource string
		Status   string
	}{
		Actor: "admin", Action: "kv.read", Resource: "app/db", Status: "success",
	}
	if _, err := sm.Update(mustCommand(t, raft.OpAuditAppend, entry)); err != nil {
		t.Fatalf("Update(audit) = %v", err)
	}

	var buf bytes.Buffer
	if err := sm.SaveSnapshot(&buf, nil, nil); err != nil {
		t.Fatalf("SaveSnapshot() = %v", err)
	}
	restored := raft.NewVaultStateMachine()
	if err := restored.RecoverFromSnapshot(&buf, nil, nil); err != nil {
		t.Fatalf("RecoverFromSnapshot() = %v", err)
	}

	got, err := restored.Lookup(raft.Command{Op: raft.OpAuditList, Payload: mustPayload(t, struct {
		Limit    int
		OrderAsc bool
	}{Limit: 10, OrderAsc: true})})
	if err != nil {
		t.Fatalf("Lookup(audit) = %v", err)
	}
	payload, ok := got.([]byte)
	if !ok || len(payload) == 0 {
		t.Fatalf("audit lookup result = %T", got)
	}
}

func TestVaultStateMachineSnapshotRoundTrip(t *testing.T) {
	sm := raft.NewVaultStateMachine()
	ca := testRootCA("root")
	out, err := sm.Update(mustCommand(t, raft.OpCASave, ca))
	if err != nil {
		t.Fatalf("Update() = %v", err)
	}
	if len(out.Data) == 0 {
		t.Fatal("expected response data")
	}

	var buf bytes.Buffer
	if err := sm.SaveSnapshot(&buf, nil, nil); err != nil {
		t.Fatalf("SaveSnapshot() = %v", err)
	}

	restored := raft.NewVaultStateMachine()
	if err := restored.RecoverFromSnapshot(&buf, nil, nil); err != nil {
		t.Fatalf("RecoverFromSnapshot() = %v", err)
	}

	got, err := restored.Lookup(raft.Command{Op: raft.OpCAGetByName, Payload: mustPayload(t, struct{ Name string }{Name: "root"})})
	if err != nil {
		t.Fatalf("Lookup() = %v", err)
	}
	payload, ok := got.([]byte)
	if !ok || len(payload) == 0 {
		t.Fatalf("lookup result = %T", got)
	}
}
