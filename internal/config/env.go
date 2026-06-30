package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kubenexis/knxvault/internal/infra/hostidentity"
	"github.com/kubenexis/knxvault/internal/version"
)

// Load reads configuration from the environment with sensible defaults.
func Load() (Config, error) {
	return overlayEnv(defaults())
}

func overlayEnv(cfg Config) (Config, error) {
	if v := os.Getenv("KNXVAULT_HTTP_ADDR"); v != "" {
		cfg.HTTPAddr = v
	}
	if v := os.Getenv("KNXVAULT_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("KNXVAULT_VERSION"); v != "" {
		cfg.Version = v
	} else {
		cfg.Version = version.Version
	}
	if v := os.Getenv("KNXVAULT_OPENSSL_BINARY"); v != "" {
		cfg.OpenSSLBinary = v
	}
	if v := os.Getenv("KNXVAULT_JWT_SECRET"); v != "" {
		cfg.JWTSecret = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_ROOT_TOKEN"); v != "" {
		cfg.RootToken = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_HA_IDENTITY"); v != "" {
		cfg.HAIdentity = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_AUDIT_SIGNING_KEY"); v != "" {
		cfg.AuditSigningKey = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_AUDIT_FORWARD_URL"); v != "" {
		cfg.AuditForwardURL = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_REQUEST_SIGNING_KEY"); v != "" {
		cfg.RequestSigningKey = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_OTLP_ENDPOINT"); v != "" {
		cfg.OTLPEndpoint = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_HA_NAMESPACE"); v != "" {
		cfg.HANamespace = v
	}
	if v := os.Getenv("KNXVAULT_HA_LEASE_NAME"); v != "" {
		cfg.HALeaseName = v
	}
	if v := os.Getenv("KNXVAULT_CORS_ALLOWED_ORIGINS"); v != "" {
		cfg.CORSAllowedOrigins = splitCSV(v)
	}

	if v := os.Getenv("KNXVAULT_SHUTDOWN_GRACE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_SHUTDOWN_GRACE: %w", err)
		}
		cfg.ShutdownGrace = d
	}
	if v := os.Getenv("KNXVAULT_OPENSSL_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_OPENSSL_TIMEOUT: %w", err)
		}
		cfg.OpenSSLTimeout = d
	}
	if v := os.Getenv("KNXVAULT_TOKEN_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_TOKEN_TTL: %w", err)
		}
		cfg.TokenTTL = d
	}
	if v := os.Getenv("KNXVAULT_HA_ENABLED"); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_HA_ENABLED: %w", err)
		}
		cfg.HAEnabled = enabled
	}
	if v := os.Getenv("KNXVAULT_JOB_LEASE_CLEANUP_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_JOB_LEASE_CLEANUP_INTERVAL: %w", err)
		}
		cfg.JobLeaseCleanupInterval = d
	}
	if v := os.Getenv("KNXVAULT_JOB_CRL_REFRESH_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_JOB_CRL_REFRESH_INTERVAL: %w", err)
		}
		cfg.JobCRLRefreshInterval = d
	}
	if v := os.Getenv("KNXVAULT_JOB_CERT_RENEW_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_JOB_CERT_RENEW_INTERVAL: %w", err)
		}
		cfg.JobCertRenewInterval = d
	}
	if v := os.Getenv("KNXVAULT_RENEW_GRACE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_RENEW_GRACE: %w", err)
		}
		cfg.RenewGrace = d
	}
	if v := os.Getenv("KNXVAULT_RATE_LIMIT_ENABLED"); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_RATE_LIMIT_ENABLED: %w", err)
		}
		cfg.RateLimitEnabled = enabled
	}
	if v := os.Getenv("KNXVAULT_RATE_LIMIT_RPM"); v != "" {
		rpm, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_RATE_LIMIT_RPM: %w", err)
		}
		cfg.RateLimitRPM = rpm
	}
	if v := os.Getenv("KNXVAULT_REQUEST_SIGNING_REQUIRED"); v != "" {
		required, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_REQUEST_SIGNING_REQUIRED: %w", err)
		}
		cfg.RequestSigningRequired = required
	}
	if v := os.Getenv("KNXVAULT_TRACING_ENABLED"); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_TRACING_ENABLED: %w", err)
		}
		cfg.TracingEnabled = enabled
	}
	if v := os.Getenv("KNXVAULT_TRACING_SAMPLE_RATIO"); v != "" {
		ratio, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_TRACING_SAMPLE_RATIO: %w", err)
		}
		cfg.TracingSampleRatio = ratio
	}
	if v := os.Getenv("KNXVAULT_K8S_AUTH_INSECURE"); v != "" {
		insecure, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_K8S_AUTH_INSECURE: %w", err)
		}
		cfg.K8sAuthInsecure = insecure
	}

	raft, err := overlayRaftEnv(cfg.Raft)
	if err != nil {
		return Config{}, err
	}
	cfg.Raft = raft
	if err := cfg.Raft.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func overlayRaftEnv(cfg RaftConfig) (RaftConfig, error) {
	if v := os.Getenv("KNXVAULT_RAFT_ADDRESS"); v != "" {
		cfg.RaftAddress = v
	}
	if v := os.Getenv("KNXVAULT_RAFT_LISTEN_ADDRESS"); v != "" {
		cfg.ListenAddress = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_RAFT_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("KNXVAULT_RAFT_INITIAL_MEMBERS"); v != "" {
		cfg.InitialMembersRaw = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_RAFT_MTLS_CERT"); v != "" {
		cfg.MTLSCertFile = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_RAFT_MTLS_KEY"); v != "" {
		cfg.MTLSKeyFile = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_RAFT_MTLS_CA"); v != "" {
		cfg.MTLSCAFile = strings.TrimSpace(v)
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
