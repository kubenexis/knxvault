// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package dto

import "time"

// AuditEntryResponse is a single audit log record.
type AuditEntryResponse struct {
	ID             int64          `json:"id"`
	Timestamp      time.Time      `json:"timestamp"`
	Actor          string         `json:"actor"`
	Action         string         `json:"action"`
	Resource       string         `json:"resource"`
	Status         string         `json:"status"`
	Details        map[string]any `json:"details"`
	Hash           string         `json:"hash"`
	AuthMethod     string         `json:"auth_method,omitempty"`
	SourceIP       string         `json:"source_ip,omitempty"`
	ClientIdentity string         `json:"client_identity,omitempty"`
	FailureReason  string         `json:"failure_reason,omitempty"`
	RequestID      string         `json:"request_id,omitempty"`
	Namespace      string         `json:"namespace,omitempty"`
}

// AuditExportResponse contains exported audit data and integrity metadata.
type AuditExportResponse struct {
	Entries   []AuditEntryResponse `json:"entries"`
	HeadHash  string               `json:"head_hash"`
	Signature string               `json:"signature,omitempty"`
	SignedAt  time.Time            `json:"signed_at"`
}

// AuditVerifyRequest verifies audit chain integrity.
type AuditVerifyRequest struct {
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
}

// AuditVerifyResponse reports verification status.
type AuditVerifyResponse struct {
	Valid     bool   `json:"valid"`
	HeadHash  string `json:"head_hash"`
	Signature string `json:"signature,omitempty"`
	Message   string `json:"message,omitempty"`
}
