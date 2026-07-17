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
	// Reject removed OpenSSL PKI settings so misconfigured clusters fail loudly.
	if v := strings.TrimSpace(os.Getenv("KNXVAULT_PKI_BACKEND")); v != "" && !strings.EqualFold(v, "native") {
		return Config{}, fmt.Errorf("KNXVAULT_PKI_BACKEND=%q is unsupported: only native Go PKI remains (OpenSSL CLI backend removed)", v)
	}
	if strings.TrimSpace(os.Getenv("KNXVAULT_OPENSSL_BINARY")) != "" {
		return Config{}, fmt.Errorf("KNXVAULT_OPENSSL_BINARY is unsupported: OpenSSL CLI PKI backend was removed (native Go crypto/x509 only)")
	}
	if strings.TrimSpace(os.Getenv("KNXVAULT_OPENSSL_TIMEOUT")) != "" {
		return Config{}, fmt.Errorf("KNXVAULT_OPENSSL_TIMEOUT is unsupported: OpenSSL CLI PKI backend was removed (native Go crypto/x509 only)")
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
	if v := os.Getenv("KNXVAULT_TLS_CERT"); v != "" {
		cfg.TLSCertFile = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_TLS_KEY"); v != "" {
		cfg.TLSKeyFile = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_MTLS_CA"); v != "" {
		cfg.MTLSCAFile = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_MTLS_REQUIRED"); v != "" {
		required, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_MTLS_REQUIRED: %w", err)
		}
		cfg.MTLSRequired = required
	}
	if v := os.Getenv("KNXVAULT_EXPOSURE_SIGNING_KEY"); v != "" {
		cfg.ExposureSigningKey = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_EXPOSURE_AUTO_REVOKE"); v != "" {
		auto, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_EXPOSURE_AUTO_REVOKE: %w", err)
		}
		cfg.ExposureAutoRevoke = auto
	}
	if v := os.Getenv("KNXVAULT_EXPOSURE_WEBHOOK_URL"); v != "" {
		cfg.ExposureWebhookURL = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_ROTATION_WEBHOOK_URL"); v != "" {
		cfg.RotationWebhookURL = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_UNSEAL_KEY"); v != "" {
		cfg.UnsealKey = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_UNSEAL_THRESHOLD"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_UNSEAL_THRESHOLD: %w", err)
		}
		cfg.UnsealThreshold = n
	}
	if v := os.Getenv("KNXVAULT_JOB_MASTER_KEY_REENCRYPT_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_JOB_MASTER_KEY_REENCRYPT_INTERVAL: %w", err)
		}
		cfg.JobMasterKeyReencryptInterval = d
	}
	if v := os.Getenv("KNXVAULT_JOB_KV_ROTATION_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_JOB_KV_ROTATION_INTERVAL: %w", err)
		}
		cfg.JobKVRotationInterval = d
	}
	if v := os.Getenv("KNXVAULT_OIDC_DEFAULT_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_OIDC_DEFAULT_TTL: %w", err)
		}
		cfg.OIDCDefaultTTL = d
	}
	if v := os.Getenv("KNXVAULT_K8S_AUTH_INSECURE"); v != "" {
		insecure, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_K8S_AUTH_INSECURE: %w", err)
		}
		cfg.K8sAuthInsecure = insecure
	}
	if v := os.Getenv("KNXVAULT_TENANT_MODE"); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_TENANT_MODE: %w", err)
		}
		cfg.TenantMode = enabled
	}
	if v := strings.TrimSpace(os.Getenv("KNXVAULT_VALKEY_CACHE_URL")); v != "" {
		cfg.ValkeyCacheURL = v
	} else if v := strings.TrimSpace(os.Getenv("KNXVAULT_REDIS_CACHE_URL")); v != "" {
		// Deprecated: use KNXVAULT_VALKEY_CACHE_URL (Redis-named env removed in favor of Valkey).
		cfg.ValkeyCacheURL = v
	}
	if v := os.Getenv("KNXVAULT_AUTH_LOCKOUT_THRESHOLD"); v != "" {
		threshold, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_AUTH_LOCKOUT_THRESHOLD: %w", err)
		}
		cfg.AuthLockoutThreshold = threshold
	}
	if v := os.Getenv("KNXVAULT_AUTH_LOCKOUT_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_AUTH_LOCKOUT_TTL: %w", err)
		}
		cfg.AuthLockoutTTL = d
	}
	if v := os.Getenv("KNXVAULT_AUTH_LOGIN_RATE_LIMIT_RPM"); v != "" {
		rpm, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_AUTH_LOGIN_RATE_LIMIT_RPM: %w", err)
		}
		cfg.AuthLoginRateLimitRPM = rpm
	}
	if v := os.Getenv("KNXVAULT_TOKEN_CREATE_RATE_LIMIT_RPM"); v != "" {
		rpm, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_TOKEN_CREATE_RATE_LIMIT_RPM: %w", err)
		}
		cfg.TokenCreateRateLimitRPM = rpm
	}
	if v := os.Getenv("KNXVAULT_RBAC_SYNC_FAIL_CLOSED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_RBAC_SYNC_FAIL_CLOSED: %w", err)
		}
		cfg.RBACSyncFailClosed = b
	}
	if v := os.Getenv("KNXVAULT_TRUSTED_PROXIES"); v != "" {
		cfg.TrustedProxies = splitCSV(v)
	}
	if v := os.Getenv("KNXVAULT_METRICS_BEARER_TOKEN"); v != "" {
		cfg.MetricsBearerToken = strings.TrimSpace(v)
	}
	if v := os.Getenv("KNXVAULT_ROOT_TOKEN_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_ROOT_TOKEN_TTL: %w", err)
		}
		cfg.RootTokenTTL = d
	}
	if v := os.Getenv("KNXVAULT_RAFT_ALLOW_INSECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_RAFT_ALLOW_INSECURE: %w", err)
		}
		cfg.RaftAllowInsecure = b
	}
	if v := os.Getenv("KNXVAULT_MANAGED_SQL_STRICT"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_MANAGED_SQL_STRICT: %w", err)
		}
		cfg.ManagedSQLStrict = b
	}
	if v := os.Getenv("KNXVAULT_REQUIRE_HTTPS_CLIENTS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_REQUIRE_HTTPS_CLIENTS: %w", err)
		}
		cfg.RequireHTTPSClients = b
	}

	raft, err := overlayRaftEnv(cfg.Raft)
	if err != nil {
		return Config{}, err
	}
	cfg.Raft = raft
	if err := cfg.Raft.Validate(); err != nil {
		return Config{}, err
	}
	if err := ValidateSecurity(cfg, ""); err != nil {
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
