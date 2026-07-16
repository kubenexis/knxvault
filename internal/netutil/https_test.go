package netutil_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/netutil"
)

func TestValidateVaultBaseURL(t *testing.T) {
	if err := netutil.ValidateVaultBaseURL("https://vault.example:8200", true); err != nil {
		t.Fatal(err)
	}
	if err := netutil.ValidateVaultBaseURL("http://127.0.0.1:8200", true); err != nil {
		t.Fatal(err)
	}
	if err := netutil.ValidateVaultBaseURL("http://localhost:8200", true); err != nil {
		t.Fatal(err)
	}
	if err := netutil.ValidateVaultBaseURL("http://vault.example:8200", true); err == nil {
		t.Fatal("expected cleartext non-loopback rejected")
	}
	if err := netutil.ValidateVaultBaseURL("http://vault.example:8200", false); err != nil {
		t.Fatal(err)
	}
}
