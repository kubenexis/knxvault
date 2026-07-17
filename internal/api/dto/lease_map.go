// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package dto

import "time"

// NewLeaseFields builds common lease response fields.
func NewLeaseFields(leaseID string, ttl, maxTTL int, expiresAt time.Time, warnings []string) LeaseFields {
	return LeaseFields{
		LeaseID:       leaseID,
		LeaseDuration: ttl,
		LeaseMaxTTL:   maxTTL,
		ExpiresAt:     expiresAt,
		Warnings:      warnings,
	}
}
