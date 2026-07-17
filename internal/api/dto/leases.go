// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package dto

import "time"

// LeaseResponse returns engine-agnostic lease metadata.
type LeaseResponse struct {
	LeaseID    string     `json:"lease_id"`
	Engine     string     `json:"engine"`
	Role       string     `json:"role"`
	Path       string     `json:"path"`
	TTLSeconds int        `json:"ttl_seconds"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Renewable  bool       `json:"renewable"`
	Revoked    bool       `json:"revoked"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	TokenID    string     `json:"token_id,omitempty"`
}

// LeaseRenewRequest renews a lease.
type LeaseRenewRequest struct {
	LeaseID    string `json:"lease_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// BulkLeaseRevokeRequest selects leases for bulk revocation.
type BulkLeaseRevokeRequest struct {
	Engine     string `json:"engine"`
	Role       string `json:"role"`
	PathPrefix string `json:"path_prefix"`
}

// BulkLeaseRevokeResponse summarizes bulk revocation.
type BulkLeaseRevokeResponse struct {
	Revoked  int      `json:"revoked"`
	LeaseIDs []string `json:"lease_ids"`
}
