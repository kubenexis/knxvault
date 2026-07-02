// Package config loads and validates KNXVault runtime configuration.
package config

import (
	"strings"
	"time"
)

const (
	defaultHTTPAddr                      = ":8200"
	defaultLogLevel                      = "info"
	defaultShutdownGrace                 = 10 * time.Second
	defaultOpenSSLTimeout                = 60 * time.Second
	defaultOpenSSLBinary                 = "openssl"
	defaultPKIBackend                    = "openssl"
	defaultTokenTTL                      = 24 * time.Hour
	defaultHANamespace                   = "knxvault"
	defaultHALeaseName                   = "knxvault-leader"
	defaultJobLeaseCleanupInterval       = 1 * time.Minute
	defaultJobCRLRefreshInterval         = 15 * time.Minute
	defaultJobCertRenewInterval          = 1 * time.Hour
	defaultJobKVRotationInterval         = 5 * time.Minute
	defaultJobMasterKeyReencryptInterval = 1 * time.Minute
	defaultRenewGrace                    = 72 * time.Hour
	defaultRateLimitRPM                  = 300
	defaultAuthLoginRateLimitRPM         = 30
	defaultTokenCreateRateLimitRPM       = 20
	defaultAuthLockoutThreshold          = 5
	defaultAuthLockoutTTL                = 15 * time.Minute
	defaultOIDCTokenTTL                  = 1 * time.Hour
)

// Config holds process-wide settings loaded from environment variables.
type Config struct {
	HTTPAddr        string
	LogLevel        string
	ShutdownGrace   time.Duration
	Version         string
	OpenSSLTimeout  time.Duration
	OpenSSLBinary   string
	PKIBackend      string
	JWTSecret       string
	K8sAuthInsecure bool
	RootToken       string
	TokenTTL        time.Duration

	HAEnabled               bool
	HANamespace             string
	HALeaseName             string
	HAIdentity              string
	JobLeaseCleanupInterval time.Duration
	JobCRLRefreshInterval   time.Duration
	AuditSigningKey         string
	AuditForwardURL         string
	CORSAllowedOrigins      []string

	JobCertRenewInterval          time.Duration
	JobKVRotationInterval         time.Duration
	JobMasterKeyReencryptInterval time.Duration
	UnsealKey                     string
	RenewGrace                    time.Duration

	TLSCertFile  string
	TLSKeyFile   string
	MTLSRequired bool
	MTLSCAFile   string

	ExposureSigningKey string
	ExposureAutoRevoke bool
	ExposureWebhookURL string
	RotationWebhookURL string

	OIDCDefaultTTL          time.Duration
	RateLimitEnabled        bool
	RateLimitRPM            int
	AuthLoginRateLimitRPM   int
	TokenCreateRateLimitRPM int
	AuthLockoutThreshold    int
	AuthLockoutTTL          time.Duration
	TenantMode              bool
	ValkeyCacheURL          string

	RequestSigningKey      string
	RequestSigningRequired bool

	TracingEnabled     bool
	OTLPEndpoint       string
	TracingSampleRatio float64

	Raft RaftConfig
}

func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
