package memlock_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto/memlock"
)

func TestLockedCopy(t *testing.T) {
	src := []byte("sensitive-key-material-32bytes!!")
	out, err := memlock.Locked(src)
	if err != nil {
		t.Fatalf("Locked() = %v", err)
	}
	if string(out) != string(src) {
		t.Fatalf("copy mismatch")
	}
	if err := memlock.Unlock(out); err != nil {
		t.Fatalf("Unlock() = %v", err)
	}
}
