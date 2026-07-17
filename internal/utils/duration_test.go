// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/utils"
)

func TestParseTTL(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"8760h", 8760 * time.Hour},
		{"365d", 365 * 24 * time.Hour},
		{"30m", 30 * time.Minute},
		{"90s", 90 * time.Second},
	}

	for _, tc := range tests {
		got, err := utils.ParseTTL(tc.in)
		if err != nil {
			t.Fatalf("ParseTTL(%q) err = %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseTTL(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseTTLRejectsNonPositiveAndHuge(t *testing.T) {
	for _, in := range []string{"-1h", "0m", "0d", "-5d"} {
		if _, err := utils.ParseTTL(in); err == nil {
			t.Fatalf("ParseTTL(%q) expected error", in)
		}
	}
	// Larger than MaxParseTTL (~10y)
	if _, err := utils.ParseTTL("4000d"); err == nil {
		t.Fatal("expected max ttl error")
	}
}
