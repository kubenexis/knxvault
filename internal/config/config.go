// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

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

	// Security profiles (M-PRODSEC-1 / A1).
	SecurityProfileLab        = "lab"
	SecurityProfileProduction = "production"

	// TLSTerminationIngress means API TLS is terminated at an ingress/load balancer;
	// the process may listen plain HTTP on a private network only.
	TLSTerminationIngress = "ingress"
	TLSTerminationServer  = "server"

	// MaxProductionRootTokenTTL is the longest allowed bootstrap root TTL in production.
	MaxProductionRootTokenTTL = 4 * time.Hour
)

// Config holds process-wide settings loaded from environment variables.
type Config struct {
	HTTPAddr        string
	LogLevel        string
	ShutdownGrace   time.Duration
	Version         string
	JWTSecret       string
	K8sAuthInsecure bool
	RootToken       string
	TokenTTL        time.Duration

	// SecurityProfile is lab (default) or production (fail-closed posture).
	// Env: KNXVAULT_SECURITY_PROFILE. YAML: security.profile.
	SecurityProfile string
	// TLSTermination is empty/server (process TLS) or ingress (edge TLS, process may be plain).
	// Env: KNXVAULT_TLS_TERMINATION. YAML: security.tls_termination.
	TLSTermination string

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
	// UnsealThreshold is Shamir t (shares required). <=1 means single-key unseal.
	UnsealThreshold int
	RenewGrace      time.Duration

	TLSCertFile  string
	TLSKeyFile   string
	MTLSRequired bool
	MTLSCAFile   string

	ExposureSigningKey string
	ExposureAutoRevoke bool
	// ExposurePathPrefixes when non-empty limits auto-rotate paths (prefix match). Empty + auto-revoke = deny path rotation (lease-only).
	ExposurePathPrefixes []string
	ExposureWebhookURL   string
	RotationWebhookURL   string
	// MasterKeyPrevious are older master keys (base64 32-byte) for decrypt after rotation (W63/W76).
	MasterKeyPrevious []string
	// MasterKeyRotationAllowInsecure allows in-process rotation on multi-node Raft without cluster key sync (lab only).
	MasterKeyRotationAllowInsecure bool

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

	// RBACSyncFailClosed denies authz when policy sync fails (W50-17). Default true in production intent.
	RBACSyncFailClosed bool
	// TrustedProxies are CIDRs/IPs for Gin ClientIP / X-Forwarded-For (W50-18). Empty = trust none.
	TrustedProxies []string
	// MetricsBearerToken when set requires Authorization: Bearer on GET /metrics (W50-19).
	MetricsBearerToken string
	// MetricsAddr when set serves /metrics on a dedicated listener (W75-03); empty = same as HTTPAddr.
	MetricsAddr string
	// UnsealAllowCIDRs restricts POST /sys/unseal source IPs (W75-04). Empty = allow all (lab).
	UnsealAllowCIDRs []string
	// Auto-unseal (W63 / P3): decrypt unseal key with KEK and unseal on start.
	AutoUnsealEnabled    bool
	AutoUnsealProvider   string // "aes-kek" | ""
	AutoUnsealCiphertext string // base64 sealed unseal key
	AutoUnsealKEK        string // base64 32-byte KEK (from KMS CSI / external)
	// RootTokenTTL overrides bootstrap root token lifetime (W50-26). Default 72h.
	RootTokenTTL time.Duration
	// RaftAllowInsecure skips multi-node Raft mTLS requirement (lab only, W50-20).
	// Also used as the lab escape hatch for K8sAuthInsecure (W52).
	RaftAllowInsecure bool
	// ManagedSQLStrict enables template-only SQL validation for managed DB roles (W50-22).
	ManagedSQLStrict bool
	// RequireHTTPSClients rejects non-HTTPS vault addresses in CSI/ESO clients (W52-06).
	// Loopback http://127.0.0.1 and http://localhost remain allowed for lab.
	RequireHTTPSClients bool

	// LDAP (W70) — optional native directory auth defaults.
	LDAPURL                string
	LDAPUserDNTemplate     string
	LDAPDefaultPolicies    []string
	LDAPInsecureSkipVerify bool

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
