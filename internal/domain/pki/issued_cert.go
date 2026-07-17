// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// IssuedCertificate tracks a leaf certificate for renewal automation (W16).
type IssuedCertificate struct {
	ID                uuid.UUID
	CAID              uuid.UUID
	Role              string
	Serial            string
	CommonName        string
	DNSNames          []string
	TTLSeconds        int
	IssuedAt          time.Time
	ExpiresAt         time.Time
	AutoRenew         bool
	RenewedFromSerial *string
}

// Validate checks required issued certificate fields.
func (c *IssuedCertificate) Validate() error {
	if c.ID == uuid.Nil {
		return fmt.Errorf("issued certificate id is required")
	}
	if c.CAID == uuid.Nil {
		return fmt.Errorf("ca id is required")
	}
	if c.Role == "" || c.Serial == "" || c.CommonName == "" {
		return fmt.Errorf("role, serial, and common_name are required")
	}
	if c.TTLSeconds <= 0 {
		return fmt.Errorf("ttl must be positive")
	}
	if c.ExpiresAt.IsZero() {
		return fmt.Errorf("expires_at is required")
	}
	return nil
}

// NeedsRenewal reports whether the cert is within the renewal window.
func (c *IssuedCertificate) NeedsRenewal(now time.Time, grace time.Duration) bool {
	if !c.AutoRenew {
		return false
	}
	return !now.Before(c.ExpiresAt.Add(-grace))
}
