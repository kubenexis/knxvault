// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package dto_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/api/dto"
)

func TestNewLeaseFields(t *testing.T) {
	exp := time.Unix(1_700_000_000, 0).UTC()
	f := dto.NewLeaseFields("lease-1", 3600, 7200, exp, []string{"warn"})
	if f.LeaseID != "lease-1" || f.LeaseDuration != 3600 || f.LeaseMaxTTL != 7200 {
		t.Fatalf("unexpected fields: %+v", f)
	}
	if !f.ExpiresAt.Equal(exp) {
		t.Fatalf("expires = %v", f.ExpiresAt)
	}
	if len(f.Warnings) != 1 || f.Warnings[0] != "warn" {
		t.Fatalf("warnings = %v", f.Warnings)
	}
}
