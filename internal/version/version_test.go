package version_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/version"
)

func TestVersionIsSemver(t *testing.T) {
	if version.Version != "0.4.3" {
		t.Fatalf("Version = %q, want 0.4.3", version.Version)
	}
}
