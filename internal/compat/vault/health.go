package vault

import "net/http"

// Health codes match HashiCorp Vault GET /v1/sys/health, which cert-manager
// uses in IsVaultInitializedAndUnsealed (accepts 200, 429, 472, 473).
const (
	HealthOK               = http.StatusOK                  // 200 initialized, unsealed, active
	HealthStandby          = 429                            // unsealed standby
	HealthDRSecondary      = 472                            // DR secondary (not used)
	HealthPerfStandby      = 473                            // performance standby (not used)
	HealthNotInitialized   = http.StatusNotImplemented      // 501
	HealthSealed           = http.StatusServiceUnavailable  // 503
)

// HealthState is the input for Vault-shaped health status selection.
type HealthState struct {
	// Initialized is true once the vault process is ready for API use.
	// KNXVault bootstraps from env master key, so this is typically always true
	// while the process is up (orthogonal to optional POST /sys/init).
	Initialized bool
	// Sealed is operational seal (POST /sys/seal).
	Sealed bool
	// Standby is true when HA is enabled and this node is not leader.
	Standby bool
}

// HealthStatusCode returns the Vault-compatible HTTP status for HealthState.
func HealthStatusCode(s HealthState) int {
	if !s.Initialized {
		return HealthNotInitialized
	}
	if s.Sealed {
		return HealthSealed
	}
	if s.Standby {
		return HealthStandby
	}
	return HealthOK
}

// HealthBody is the JSON body for GET /v1/sys/health (subset of Vault fields).
type HealthBody struct {
	Initialized                bool   `json:"initialized"`
	Sealed                     bool   `json:"sealed"`
	Standby                    bool   `json:"standby"`
	PerformanceStandby         bool   `json:"performance_standby"`
	ReplicationPerformanceMode string `json:"replication_performance_mode"`
	ReplicationDRMode          string `json:"replication_dr_mode"`
	ServerTimeUTC              int64  `json:"server_time_utc"`
	Version                    string `json:"version"`
	ClusterName                string `json:"cluster_name,omitempty"`
	ClusterID                  string `json:"cluster_id,omitempty"`
}

// NewHealthBody builds a Vault-shaped health payload.
func NewHealthBody(s HealthState, version string, serverTimeUTC int64) HealthBody {
	return HealthBody{
		Initialized:                s.Initialized,
		Sealed:                     s.Sealed,
		Standby:                    s.Standby,
		PerformanceStandby:         false,
		ReplicationPerformanceMode: "disabled",
		ReplicationDRMode:          "disabled",
		ServerTimeUTC:              serverTimeUTC,
		Version:                    version,
		ClusterName:                "knxvault",
	}
}
