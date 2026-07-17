// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestMatchResourceGlobSingleStarNoSlash(t *testing.T) {
	if !auth.MatchResourceGlob("secrets/kv/*", "secrets/kv/a") {
		t.Fatal("single segment should match")
	}
	if auth.MatchResourceGlob("secrets/kv/*", "secrets/kv/a/b") {
		t.Fatal("single * must not match multi-segment")
	}
	if !auth.MatchResourceGlob("secrets/kv/**", "secrets/kv/a/b") {
		t.Fatal("** should match multi-segment")
	}
	if !auth.MatchResourceGlob("secrets/*/*", "secrets/kv/a") {
		t.Fatal("two single stars")
	}
}
