// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package auth

import "testing"

func TestFlattenRolePoliciesMergesGroups(t *testing.T) {
	got := flattenRolePolicies([]string{"base"}, []string{"team-a", "base"})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %v", len(got), got)
	}
	if got[0] != "base" || got[1] != "team-a" {
		t.Fatalf("unexpected order: %v", got)
	}
}
