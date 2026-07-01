package sensitive_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto/sensitive"
)

func TestBufferCloseZeroes(t *testing.T) {
	buf, err := sensitive.New([]byte("secret"))
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	b := buf.Bytes()
	buf.Close()
	for _, c := range b {
		if c != 0 {
			t.Fatalf("expected zeroed buffer after Close")
		}
	}
}
