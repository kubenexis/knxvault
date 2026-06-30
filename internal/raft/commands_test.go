package raft

import "testing"

func TestIsReadOnlyOp(t *testing.T) {
	readOps := []string{
		OpCAGetByID, OpCAGetByName, OpCAList,
		OpSecretGetLatest, OpAuditList, OpAuditLatestHash,
		OpIssuedListExpiring,
	}
	for _, op := range readOps {
		if !IsReadOnlyOp(op) {
			t.Fatalf("expected %q to be read-only", op)
		}
	}

	writeOps := []string{
		OpCASave, OpAuditAppend, OpImportSnapshot, OpSecretSaveVersion,
	}
	for _, op := range writeOps {
		if IsReadOnlyOp(op) {
			t.Fatalf("expected %q to be write-only", op)
		}
	}
}
