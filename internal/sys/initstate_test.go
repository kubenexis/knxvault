// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package sys_test

import (
	"errors"
	"testing"

	"github.com/kubenexis/knxvault/internal/sys"
)

func TestMarkInitializedRejectsSecondCall(t *testing.T) {
	sys.ResetForTest()
	if err := sys.MarkInitialized("abc123"); err != nil {
		t.Fatalf("MarkInitialized() = %v", err)
	}
	if !sys.Initialized() {
		t.Fatal("expected initialized after first MarkInitialized")
	}
	if sys.MasterKeyFingerprint() != "abc123" {
		t.Fatalf("fingerprint = %q", sys.MasterKeyFingerprint())
	}
	err := sys.MarkInitialized("def456")
	if !errors.Is(err, sys.ErrAlreadyInitialized) {
		t.Fatalf("second MarkInitialized() = %v, want ErrAlreadyInitialized", err)
	}
}
