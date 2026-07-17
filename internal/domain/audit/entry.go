// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"time"
)

// Entry is an append-only audit log record (LLD §4.D.1).
type Entry struct {
	ID             int64          `json:"id"`
	Timestamp      time.Time      `json:"timestamp"`
	Actor          string         `json:"actor"`
	Action         string         `json:"action"`
	Resource       string         `json:"resource"`
	Status         string         `json:"status"`
	Details        map[string]any `json:"details,omitempty"`
	Hash           string         `json:"hash"`
	Signature      string         `json:"signature,omitempty"`
	AuthMethod     string         `json:"auth_method,omitempty"`
	SourceIP       string         `json:"source_ip,omitempty"`
	ClientIdentity string         `json:"client_identity,omitempty"`
	FailureReason  string         `json:"failure_reason,omitempty"`
	RequestID      string         `json:"request_id,omitempty"`
	Namespace      string         `json:"namespace,omitempty"`
}

// Validate checks required audit fields.
func (e *Entry) Validate() error {
	if e.Action == "" {
		return fmt.Errorf("audit action is required")
	}
	if e.Status == "" {
		return fmt.Errorf("audit status is required")
	}
	return nil
}
