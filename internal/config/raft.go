package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kubenexis/knxvault/internal/infra/hostidentity"
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
	return nil
}

func loadRaftConfig() (RaftConfig, error) {
	cfg := RaftConfig{
		LeaderWait:        defaultRaftLeaderWait,
		RaftAddress:       envOr("KNXVAULT_RAFT_ADDRESS", defaultRaftAddress),
		ListenAddress:     strings.TrimSpace(os.Getenv("KNXVAULT_RAFT_LISTEN_ADDRESS")),
		DataDir:           envOr("KNXVAULT_RAFT_DATA_DIR", defaultRaftDataDir),
		ElectionRTT:       defaultRaftElectionRTT,
		HeartbeatRTT:      defaultRaftHeartbeatRTT,
		RTTMillisecond:    defaultRaftRTTMillisecond,
		InitialMembersRaw: strings.TrimSpace(os.Getenv("KNXVAULT_RAFT_INITIAL_MEMBERS")),
		MTLSCertFile:      strings.TrimSpace(os.Getenv("KNXVAULT_RAFT_MTLS_CERT")),
		MTLSKeyFile:       strings.TrimSpace(os.Getenv("KNXVAULT_RAFT_MTLS_KEY")),
		MTLSCAFile:        strings.TrimSpace(os.Getenv("KNXVAULT_RAFT_MTLS_CA")),
	}

	if v := os.Getenv("KNXVAULT_RAFT_ENABLED"); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return RaftConfig{}, fmt.Errorf("KNXVAULT_RAFT_ENABLED: %w", err)
		}
		cfg.Enabled = enabled
	}

	if v := os.Getenv("KNXVAULT_RAFT_NODE_ID"); v != "" {
		id, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return RaftConfig{}, fmt.Errorf("KNXVAULT_RAFT_NODE_ID: %w", err)
		}
		cfg.NodeID = id
	}

	if v := os.Getenv("KNXVAULT_RAFT_ELECTION_RTT"); v != "" {
		val, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return RaftConfig{}, fmt.Errorf("KNXVAULT_RAFT_ELECTION_RTT: %w", err)
		}
		cfg.ElectionRTT = val
	}

	if v := os.Getenv("KNXVAULT_RAFT_HEARTBEAT_RTT"); v != "" {
		val, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return RaftConfig{}, fmt.Errorf("KNXVAULT_RAFT_HEARTBEAT_RTT: %w", err)
		}
		cfg.HeartbeatRTT = val
	}

	if v := os.Getenv("KNXVAULT_RAFT_RTT_MILLISECOND"); v != "" {
		val, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return RaftConfig{}, fmt.Errorf("KNXVAULT_RAFT_RTT_MILLISECOND: %w", err)
		}
		cfg.RTTMillisecond = val
	}

	if v := os.Getenv("KNXVAULT_RAFT_LEADER_WAIT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return RaftConfig{}, fmt.Errorf("KNXVAULT_RAFT_LEADER_WAIT: %w", err)
		}
		cfg.LeaderWait = d
	}

	if v := os.Getenv("KNXVAULT_RAFT_JOIN"); v != "" {
		join, err := strconv.ParseBool(v)
		if err != nil {
			return RaftConfig{}, fmt.Errorf("KNXVAULT_RAFT_JOIN: %w", err)
		}
		cfg.Join = join
	}

	if cfg.NodeID == 0 {
		if id := hostidentity.NodeIDFromHostname(hostidentity.Hostname()); id > 0 {
			cfg.NodeID = id
		}
	}

	return cfg, nil
}
