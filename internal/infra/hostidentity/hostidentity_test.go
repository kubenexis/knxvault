package hostidentity_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/infra/hostidentity"
)

func TestNodeIDFromHostname(t *testing.T) {
	tests := []struct {
		host string
		want uint64
	}{
		{"knxvault-0", 1},
		{"knxvault-2", 3},
		{"single", 0},
		{"pod-name-x", 0},
	}
	for _, tc := range tests {
		if got := hostidentity.NodeIDFromHostname(tc.host); got != tc.want {
			t.Fatalf("NodeIDFromHostname(%q) = %d, want %d", tc.host, got, tc.want)
		}
	}
}

func TestHostnamePrefersPodNameEnv(t *testing.T) {
	t.Setenv("KNXVAULT_POD_NAME", "knxvault-1")
	t.Setenv("HOSTNAME", "ignored")
	if got := hostidentity.Hostname(); got != "knxvault-1" {
		t.Fatalf("Hostname() = %q, want knxvault-1", got)
	}
}
