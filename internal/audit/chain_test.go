// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/audit"
)

func TestValidateRecordChain(t *testing.T) {
	now := time.Now().UTC()
	first := audit.Record{
		Timestamp: now,
		Actor:     "admin",
		Action:    "kv.read",
		Resource:  "app/db",
		Status:    "success",
	}
	first.Hash = audit.EntryHash("", first.Actor, first.Action, first.Resource, first.Status, first.Details, first.Timestamp)
	second := audit.Record{
		Timestamp: now.Add(time.Second),
		Actor:     "admin",
		Action:    "kv.write",
		Resource:  "app/db",
		Status:    "success",
	}
	second.Hash = audit.EntryHash(first.Hash, second.Actor, second.Action, second.Resource, second.Status, second.Details, second.Timestamp)

	if err := audit.ValidateRecordChain([]audit.Record{first, second}); err != nil {
		t.Fatalf("ValidateRecordChain() = %v", err)
	}
	if err := audit.ValidateRecordChain([]audit.Record{first, {Hash: "bad"}}); err == nil {
		t.Fatal("expected hash mismatch error")
	}
}
