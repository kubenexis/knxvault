// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/audit"
)

// EntryHash computes the chained hash for an audit entry.
func EntryHash(prevHash, actor, action, resource, status string, details map[string]any, ts time.Time) string {
	return computeHash(prevHash, actor, action, resource, status, details, ts)
}

// ValidateChain verifies hash-chain integrity for ordered audit entries.
func ValidateChain(entries []*audit.Entry) error {
	prevHash := ""
	for i, entry := range entries {
		if entry == nil {
			return fmt.Errorf("audit entry %d is nil", i)
		}
		expected := EntryHash(prevHash, entry.Actor, entry.Action, entry.Resource, entry.Status, entry.Details, entry.Timestamp)
		if entry.Hash != expected {
			return fmt.Errorf("audit entry %d hash mismatch", i)
		}
		prevHash = entry.Hash
	}
	return nil
}

// ValidateRecordChain verifies portable audit records in backup order.
func ValidateRecordChain(records []Record) error {
	prevHash := ""
	for i, rec := range records {
		expected := EntryHash(prevHash, rec.Actor, rec.Action, rec.Resource, rec.Status, rec.Details, rec.Timestamp)
		if rec.Hash != expected {
			return fmt.Errorf("audit record %d hash mismatch", i)
		}
		prevHash = rec.Hash
	}
	return nil
}

// Record is a portable audit entry for backup validation.
type Record struct {
	Timestamp time.Time
	Actor     string
	Action    string
	Resource  string
	Status    string
	Details   map[string]any
	Hash      string
}
