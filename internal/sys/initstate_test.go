package sys_test

import (
	"errors"
	"testing"

	"github.com/kubenexis/knxvault/internal/sys"
)

func TestMarkInitializedRejectsSecondCall(t *testing.T) {
	if sys.Initialized() {
		t.Skip("bootstrap state already set in this process")
	}
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