// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package dto

// BackupCreateRequest configures POST /sys/backup.
type BackupCreateRequest struct {
	IncludeAudit bool `json:"include_audit"`
	AuditLimit   int  `json:"audit_limit"`
}

// BackupCreateResponse returns an encrypted backup archive.
type BackupCreateResponse struct {
	Format string `json:"format"`
	Data   string `json:"data"`
}
