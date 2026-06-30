// Package config loads and validates KNXVault runtime configuration.
package config

import (
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
	defaultJobKVRotationInterval   = 5 * time.Minute
	defaultRenewGrace              = 72 * time.Hour
	defaultRateLimitRPM            = 300
	defaultOIDCTokenTTL            = 1 * time.Hour
)

// Config holds process-wide settings loaded from environment variables.
type Config struct {
	HTTPAddr        string
	LogLevel        string
	ShutdownGrace   time.Duration
	Version         string
	OpenSSLTimeout  time.Duration
	OpenSSLBinary   string
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

	JobCertRenewInterval  time.Duration
	JobKVRotationInterval time.Duration
	RenewGrace            time.Duration

	TLSCertFile  string
	TLSKeyFile   string
	MTLSRequired bool
	MTLSCAFile   string

	ExposureSigningKey string
	ExposureAutoRevoke bool
	ExposureWebhookURL string
	RotationWebhookURL string

	OIDCDefaultTTL         time.Duration
	RateLimitEnabled       bool
	RateLimitRPM           int
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
