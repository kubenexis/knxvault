package vault_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/compat/vault"
)

func TestHealthStatusCode(t *testing.T) {
	tests := []struct {
		name string
		s    vault.HealthState
		want int
	}{
		{"ok", vault.HealthState{Initialized: true}, vault.HealthOK},
		{"sealed", vault.HealthState{Initialized: true, Sealed: true}, vault.HealthSealed},
		{"standby", vault.HealthState{Initialized: true, Standby: true}, vault.HealthStandby},
		{"not init", vault.HealthState{Initialized: false}, vault.HealthNotInitialized},
		{"sealed wins over standby", vault.HealthState{Initialized: true, Sealed: true, Standby: true}, vault.HealthSealed},
		{"not init wins", vault.HealthState{Initialized: false, Sealed: true}, vault.HealthNotInitialized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vault.HealthStatusCode(tt.s); got != tt.want {
				t.Fatalf("HealthStatusCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNewHealthBody(t *testing.T) {
	body := vault.NewHealthBody(vault.HealthState{Initialized: true, Sealed: false}, "1.2.3", 1700000000)
	if !body.Initialized || body.Sealed {
		t.Fatalf("unexpected flags: %+v", body)
	}
	if body.Version != "1.2.3" || body.ServerTimeUTC != 1700000000 {
		t.Fatalf("unexpected body: %+v", body)
	}
	if body.ClusterName != "knxvault" {
		t.Fatalf("cluster_name = %q", body.ClusterName)
	}
}
