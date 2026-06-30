// Package config loads and validates KNXVault runtime configuration.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPAddr                = ":8200"
	defaultLogLevel                = "info"
	defaultShutdownGrace           = 10 * time.Second
	defaultOpenSSLTimeout          = 60 * time.Second
	defaultOpenSSLBinary           = "openssl"
	defaultTokenTTL                = 24 * time.Hour
	defaultHANamespace             = "knxvault"
	defaultHALeaseName             = "knxvault-leader"
	defaultJobLeaseCleanupInterval = 1 * time.Minute
	defaultJobCRLRefreshInterval   = 15 * time.Minute
	defaultJobCertRenewInterval    = 1 * time.Hour
	defaultRenewGrace              = 72 * time.Hour
	defaultRateLimitRPM            = 300
)

// Config holds process-wide settings loaded from environment variables.
type Config struct {
	HTTPAddr       string
	LogLevel       string
	ShutdownGrace  time.Duration
	Version        string
	OpenSSLTimeout time.Duration
	OpenSSLBinary  string
	DatabaseURL    string
	AutoMigrate    bool
	JWTSecret      string
	RootToken      string
	TokenTTL       time.Duration

	HAEnabled               bool
	HANamespace             string
	HALeaseName             string
	HAIdentity              string
	JobLeaseCleanupInterval time.Duration
	JobCRLRefreshInterval   time.Duration
	AuditSigningKey         string

	JobCertRenewInterval   time.Duration
	RenewGrace             time.Duration
	RateLimitEnabled       bool
	RateLimitRPM           int
	RequestSigningKey      string
	RequestSigningRequired bool

	TracingEnabled     bool
	OTLPEndpoint       string
	TracingSampleRatio float64
}

// Load reads configuration from the environment with sensible defaults.
func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:                envOr("KNXVAULT_HTTP_ADDR", defaultHTTPAddr),
		LogLevel:                envOr("KNXVAULT_LOG_LEVEL", defaultLogLevel),
		ShutdownGrace:           defaultShutdownGrace,
		Version:                 envOr("KNXVAULT_VERSION", "0.1.0-dev"),
		OpenSSLTimeout:          defaultOpenSSLTimeout,
		OpenSSLBinary:           envOr("KNXVAULT_OPENSSL_BINARY", defaultOpenSSLBinary),
		DatabaseURL:             strings.TrimSpace(os.Getenv("KNXVAULT_DATABASE_URL")),
		AutoMigrate:             true,
		JWTSecret:               strings.TrimSpace(os.Getenv("KNXVAULT_JWT_SECRET")),
		RootToken:               strings.TrimSpace(os.Getenv("KNXVAULT_ROOT_TOKEN")),
		TokenTTL:                defaultTokenTTL,
		HANamespace:             envOr("KNXVAULT_HA_NAMESPACE", defaultHANamespace),
		HALeaseName:             envOr("KNXVAULT_HA_LEASE_NAME", defaultHALeaseName),
		HAIdentity:              strings.TrimSpace(os.Getenv("KNXVAULT_HA_IDENTITY")),
		JobLeaseCleanupInterval: defaultJobLeaseCleanupInterval,
		JobCRLRefreshInterval:   defaultJobCRLRefreshInterval,
		AuditSigningKey:         strings.TrimSpace(os.Getenv("KNXVAULT_AUDIT_SIGNING_KEY")),
		JobCertRenewInterval:    defaultJobCertRenewInterval,
		RenewGrace:              defaultRenewGrace,
		RateLimitRPM:            defaultRateLimitRPM,
		RequestSigningKey:       strings.TrimSpace(os.Getenv("KNXVAULT_REQUEST_SIGNING_KEY")),
		OTLPEndpoint:            strings.TrimSpace(os.Getenv("KNXVAULT_OTLP_ENDPOINT")),
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

	if v := os.Getenv("KNXVAULT_AUTO_MIGRATE"); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("KNXVAULT_AUTO_MIGRATE: %w", err)
		}
		cfg.AutoMigrate = enabled
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

	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
