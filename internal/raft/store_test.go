package raft

import (
	"encoding/json"
	"testing"

	"github.com/kubenexis/knxvault/internal/domain/audit"
)

func TestLookupRejectsWriteCommand(t *testing.T) {
	store := NewStore()
	payload, err := json.Marshal(audit.Entry{
		Action: "test",
		Status: "success",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp, err := store.Lookup(Command{Op: OpAuditAppend, Payload: payload})
	if err != nil {
		t.Fatalf("Lookup(write) = %v", err)
	}
	var writeResp Response
	if err := json.Unmarshal(resp, &writeResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if writeResp.ErrorCode != "validation_error" {
		t.Fatalf("expected validation_error, got %+v", writeResp)
	}

	resp, err = store.Lookup(Command{Op: OpAuditLatestHash})
	if err != nil {
		t.Fatalf("Lookup(read) = %v", err)
	}
	var decoded Response
	if err := json.Unmarshal(resp, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.ErrorCode != "" {
		t.Fatalf("unexpected error: %+v", decoded)
	}
}