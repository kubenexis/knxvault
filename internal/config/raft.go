package config

import (
	"fmt"
	"strings"
	"time"
)

const (
	defaultRaftDataDir        = "/var/lib/knxvault/raft"
	defaultRaftAddress        = "127.0.0.1:63001"
	defaultRaftElectionRTT    = 10
	defaultRaftHeartbeatRTT   = 1
	defaultRaftRTTMillisecond = 1
	defaultRaftLeaderWait     = 10 * time.Second
)

// RaftConfig configures the Dragonboat-backed storage backend.
type RaftConfig struct {
	Enabled           bool
	NodeID            uint64
	RaftAddress       string
	ListenAddress     string
	DataDir           string
	InitialMembers    map[uint64]string
	InitialMembersRaw string
	ElectionRTT       uint64
	HeartbeatRTT      uint64
	RTTMillisecond    uint64
	Join              bool
	MTLSCertFile      string
	MTLSKeyFile       string
	MTLSCAFile        string
	LeaderWait        time.Duration
}

// Validate checks Raft settings when enabled.
func (r RaftConfig) Validate() error {
	if !r.Enabled {
		return nil
	}
	if r.NodeID == 0 {
		return fmt.Errorf("KNXVAULT_RAFT_NODE_ID must be > 0 when raft is enabled")
	}
	if strings.TrimSpace(r.RaftAddress) == "" {
		return fmt.Errorf("KNXVAULT_RAFT_ADDRESS is required when raft is enabled")
	}
	if strings.TrimSpace(r.DataDir) == "" {
		return fmt.Errorf("KNXVAULT_RAFT_DATA_DIR is required when raft is enabled")
	}
	if r.ElectionRTT == 0 || r.HeartbeatRTT == 0 {
		return fmt.Errorf("raft election and heartbeat RTT must be > 0")
	}
	if r.ElectionRTT <= 2*r.HeartbeatRTT {
		return fmt.Errorf("raft election RTT must be > 2 * heartbeat RTT")
	}
	if err := validateRaftMTLS(r.MTLSCertFile, r.MTLSKeyFile, r.MTLSCAFile); err != nil {
		return err
	}
	return nil
}

func validateRaftMTLS(cert, key, ca string) error {
	set := cert != "" || key != "" || ca != ""
	if !set {
		return nil
	}
	if cert == "" || key == "" || ca == "" {
		return fmt.Errorf("raft mTLS requires KNXVAULT_RAFT_MTLS_CERT, KEY, and CA")
	}
	return nil
}
