package raft_test

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/kubenexis/knxvault/internal/backup"
	"github.com/kubenexis/knxvault/internal/raft"
)

func TestImportSnapshotValidatesBeforeRestore(t *testing.T) {
	store := raft.NewStore()
	snapshot := &backup.Snapshot{
		Version: 1,
		CAs: []backup.CARecord{{
			ID:   uuid.New(),
			Name: "child",
			ParentID: func() *uuid.UUID {
				id := uuid.New()
				return &id
			}(),
		}},
	}
	if err := store.ImportSnapshot(snapshot); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestExportSnapshotHandler(t *testing.T) {
	store := raft.NewStore()
	ca := testRootCA("export-root")
	payload, err := json.Marshal(ca)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := store.Handle(raft.Command{Op: raft.OpCASave, Payload: payload}); err != nil {
		t.Fatalf("Handle() = %v", err)
	}

	resp, err := store.Lookup(raft.Command{Op: raft.OpExportSnapshot})
	if err != nil {
		t.Fatalf("Lookup() = %v", err)
	}
	var snapshot backup.Snapshot
	if err := raft.DecodeResult(resp, &snapshot); err != nil {
		t.Fatalf("DecodeResult() = %v", err)
	}
	if len(snapshot.CAs) != 1 || snapshot.CAs[0].Name != "export-root" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}
