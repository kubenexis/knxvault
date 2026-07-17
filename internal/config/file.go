// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultConfigFile is the default daemon configuration path when present on disk.
const DefaultConfigFile = "/etc/knxvault.conf"

// File is the YAML configuration schema (gopkg.in/yaml.v3).
type File struct {
	HTTPAddr        string        `yaml:"http_addr,omitempty"`
	LogLevel        string        `yaml:"log_level,omitempty"`
	ShutdownGrace   string        `yaml:"shutdown_grace,omitempty"`
	JWTSecret       string        `yaml:"jwt_secret,omitempty"`
	RootToken       string        `yaml:"root_token,omitempty"`
	TokenTTL        string        `yaml:"token_ttl,omitempty"`
	K8sAuthInsecure *bool         `yaml:"k8s_auth_insecure,omitempty"`
	HA              *HAFile       `yaml:"ha,omitempty"`
	Jobs            *JobsFile     `yaml:"jobs,omitempty"`
	Audit           *AuditFile    `yaml:"audit,omitempty"`
	Security        *SecurityFile `yaml:"security,omitempty"`
	Tracing         *TracingFile  `yaml:"tracing,omitempty"`
	Raft            *RaftFile     `yaml:"raft,omitempty"`
}

// HAFile configures Kubernetes leader election.
type HAFile struct {
	Enabled   *bool  `yaml:"enabled,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
	LeaseName string `yaml:"lease_name,omitempty"`
	Identity  string `yaml:"identity,omitempty"`
}

// JobsFile configures background job intervals.
type JobsFile struct {
	LeaseCleanupInterval string `yaml:"lease_cleanup_interval,omitempty"`
	CRLRefreshInterval   string `yaml:"crl_refresh_interval,omitempty"`
	CertRenewInterval    string `yaml:"cert_renew_interval,omitempty"`
	KVRotationInterval   string `yaml:"kv_rotation_interval,omitempty"`
	RenewGrace           string `yaml:"renew_grace,omitempty"`
}

// AuditFile configures audit export and forwarding.
type AuditFile struct {
	SigningKey string `yaml:"signing_key,omitempty"`
	ForwardURL string `yaml:"forward_url,omitempty"`
	// ForwardEnabled when false ignores ForwardURL (M-DTP-2 / W90-21).
	ForwardEnabled *bool `yaml:"forward_enabled,omitempty"`
}

// SecurityFile configures rate limiting, signing, CORS, TLS, and security profile.
type SecurityFile struct {
	// Profile is lab (default) or production (M-PRODSEC-1 fail-closed posture).
	Profile string `yaml:"profile,omitempty"`
	// TLSTermination is server (process TLS) or ingress (edge TLS).
	TLSTermination string `yaml:"tls_termination,omitempty"`
	// MetricsBearerToken requires Authorization: Bearer on GET /metrics (production required).
	MetricsBearerToken string `yaml:"metrics_bearer_token,omitempty"`
	// UnsealAllowCIDRs restricts POST /sys/unseal (required in production).
	UnsealAllowCIDRs       []string `yaml:"unseal_allow_cidrs,omitempty"`
	RateLimitEnabled       *bool    `yaml:"rate_limit_enabled,omitempty"`
	RateLimitRPM           *int     `yaml:"rate_limit_rpm,omitempty"`
	RequestSigningKey      string   `yaml:"request_signing_key,omitempty"`
	RequestSigningRequired *bool    `yaml:"request_signing_required,omitempty"`
	CORSAllowedOrigins     []string `yaml:"cors_allowed_origins,omitempty"`
	TLSCert                string   `yaml:"tls_cert,omitempty"`
	TLSKey                 string   `yaml:"tls_key,omitempty"`
	MTLSRequired           *bool    `yaml:"mtls_required,omitempty"`
	MTLSCA                 string   `yaml:"mtls_ca,omitempty"`
	ExposureSigningKey     string   `yaml:"exposure_signing_key,omitempty"`
	ExposureAutoRevoke     *bool    `yaml:"exposure_auto_revoke,omitempty"`
	ExposureWebhookURL     string   `yaml:"exposure_webhook_url,omitempty"`
	RotationWebhookURL     string   `yaml:"rotation_webhook_url,omitempty"`
	// AllowCoarsePKIWrite enables legacy "pki" write fallback (lab only; production forces off).
	AllowCoarsePKIWrite *bool `yaml:"allow_coarse_pki_write,omitempty"`
	// Feature gates (M-DTP-2).
	AuthOIDCEnabled    *bool `yaml:"auth_oidc_enabled,omitempty"`
	AuthLDAPEnabled    *bool `yaml:"auth_ldap_enabled,omitempty"`
	ACMERelatedEnabled *bool `yaml:"acme_related_enabled,omitempty"`
}

// TracingFile configures OpenTelemetry export.
type TracingFile struct {
	Enabled      *bool    `yaml:"enabled,omitempty"`
	OTLPEndpoint string   `yaml:"otlp_endpoint,omitempty"`
	SampleRatio  *float64 `yaml:"sample_ratio,omitempty"`
}

// RaftFile configures the Dragonboat storage backend.
type RaftFile struct {
	Enabled        *bool   `yaml:"enabled,omitempty"`
	NodeID         *uint64 `yaml:"node_id,omitempty"`
	Address        string  `yaml:"address,omitempty"`
	ListenAddress  string  `yaml:"listen_address,omitempty"`
	DataDir        string  `yaml:"data_dir,omitempty"`
	InitialMembers string  `yaml:"initial_members,omitempty"`
	ElectionRTT    *uint64 `yaml:"election_rtt,omitempty"`
	HeartbeatRTT   *uint64 `yaml:"heartbeat_rtt,omitempty"`
	RTTMillisecond *uint64 `yaml:"rtt_millisecond,omitempty"`
	LeaderWait     string  `yaml:"leader_wait,omitempty"`
	Join           *bool   `yaml:"join,omitempty"`
	MTLSCert       string  `yaml:"mtls_cert,omitempty"`
	MTLSKey        string  `yaml:"mtls_key,omitempty"`
	MTLSCA         string  `yaml:"mtls_ca,omitempty"`
}

// ResolveConfigPath picks the configuration file to load.
// An explicit flagPath wins; otherwise DefaultConfigFile is used when it exists.
// Returns "" to indicate environment-only configuration.
func ResolveConfigPath(flagPath string) string {
	if p := strings.TrimSpace(flagPath); p != "" {
		return p
	}
	if _, err := os.Stat(DefaultConfigFile); err == nil {
		return DefaultConfigFile
	}
	return ""
}

// LoadResolved loads configuration from an optional CLI path, the default file, or environment only.
func LoadResolved(flagPath string) (Config, error) {
	if path := ResolveConfigPath(flagPath); path != "" {
		return LoadFile(path)
	}
	return Load()
}

// LoadFile reads a YAML config file as the base settings, then applies environment overrides.
func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var file File
	if err := yaml.Unmarshal(data, &file); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg, err := applyFile(defaults(), file)
	if err != nil {
		return Config{}, err
	}
	cfg, err = overlayEnv(cfg)
	if err != nil {
		return Config{}, err
	}
	// overlayEnv already applied profile defaults + ValidateSecurity("") ;
	// re-validate with config path for permission checks.
	if err := ValidateSecurity(cfg, path); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyFile(cfg Config, file File) (Config, error) {
	if v := strings.TrimSpace(file.HTTPAddr); v != "" {
		cfg.HTTPAddr = v
	}
	if v := strings.TrimSpace(file.LogLevel); v != "" {
		cfg.LogLevel = v
	}
	if v := strings.TrimSpace(file.ShutdownGrace); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("shutdown_grace: %w", err)
		}
		cfg.ShutdownGrace = d
	}
	if v := strings.TrimSpace(file.JWTSecret); v != "" {
		cfg.JWTSecret = v
	}
	if v := strings.TrimSpace(file.RootToken); v != "" {
		cfg.RootToken = v
	}
	if v := strings.TrimSpace(file.TokenTTL); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("token_ttl: %w", err)
		}
		cfg.TokenTTL = d
	}
	if file.K8sAuthInsecure != nil {
		cfg.K8sAuthInsecure = *file.K8sAuthInsecure
	}
	if file.HA != nil {
		if file.HA.Enabled != nil {
			cfg.HAEnabled = *file.HA.Enabled
		}
		if v := strings.TrimSpace(file.HA.Namespace); v != "" {
			cfg.HANamespace = v
		}
		if v := strings.TrimSpace(file.HA.LeaseName); v != "" {
			cfg.HALeaseName = v
		}
		if v := strings.TrimSpace(file.HA.Identity); v != "" {
			cfg.HAIdentity = v
		}
	}
	if file.Jobs != nil {
		if v := strings.TrimSpace(file.Jobs.LeaseCleanupInterval); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("jobs.lease_cleanup_interval: %w", err)
			}
			cfg.JobLeaseCleanupInterval = d
		}
		if v := strings.TrimSpace(file.Jobs.CRLRefreshInterval); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("jobs.crl_refresh_interval: %w", err)
			}
			cfg.JobCRLRefreshInterval = d
		}
		if v := strings.TrimSpace(file.Jobs.CertRenewInterval); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("jobs.cert_renew_interval: %w", err)
			}
			cfg.JobCertRenewInterval = d
		}
		if v := strings.TrimSpace(file.Jobs.RenewGrace); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("jobs.renew_grace: %w", err)
			}
			cfg.RenewGrace = d
		}
		if v := strings.TrimSpace(file.Jobs.KVRotationInterval); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("jobs.kv_rotation_interval: %w", err)
			}
			cfg.JobKVRotationInterval = d
		}
	}
	if file.Audit != nil {
		if v := strings.TrimSpace(file.Audit.SigningKey); v != "" {
			cfg.AuditSigningKey = v
		}
		if v := strings.TrimSpace(file.Audit.ForwardURL); v != "" {
			cfg.AuditForwardURL = v
		}
		if file.Audit.ForwardEnabled != nil {
			cfg.AuditForwardEnabled = *file.Audit.ForwardEnabled
		}
	}
	if file.Security != nil {
		if v := strings.TrimSpace(file.Security.Profile); v != "" {
			cfg.SecurityProfile = v
		}
		if v := strings.TrimSpace(file.Security.TLSTermination); v != "" {
			cfg.TLSTermination = v
		}
		if v := strings.TrimSpace(file.Security.MetricsBearerToken); v != "" {
			cfg.MetricsBearerToken = v
		}
		if len(file.Security.UnsealAllowCIDRs) > 0 {
			cfg.UnsealAllowCIDRs = append([]string(nil), file.Security.UnsealAllowCIDRs...)
		}
		if file.Security.RateLimitEnabled != nil {
			cfg.RateLimitEnabled = *file.Security.RateLimitEnabled
		}
		if file.Security.RateLimitRPM != nil {
			cfg.RateLimitRPM = *file.Security.RateLimitRPM
		}
		if v := strings.TrimSpace(file.Security.RequestSigningKey); v != "" {
			cfg.RequestSigningKey = v
		}
		if file.Security.RequestSigningRequired != nil {
			cfg.RequestSigningRequired = *file.Security.RequestSigningRequired
		}
		if len(file.Security.CORSAllowedOrigins) > 0 {
			cfg.CORSAllowedOrigins = append([]string(nil), file.Security.CORSAllowedOrigins...)
		}
		if v := strings.TrimSpace(file.Security.TLSCert); v != "" {
			cfg.TLSCertFile = v
		}
		if v := strings.TrimSpace(file.Security.TLSKey); v != "" {
			cfg.TLSKeyFile = v
		}
		if file.Security.MTLSRequired != nil {
			cfg.MTLSRequired = *file.Security.MTLSRequired
		}
		if v := strings.TrimSpace(file.Security.MTLSCA); v != "" {
			cfg.MTLSCAFile = v
		}
		if v := strings.TrimSpace(file.Security.ExposureSigningKey); v != "" {
			cfg.ExposureSigningKey = v
		}
		if file.Security.ExposureAutoRevoke != nil {
			cfg.ExposureAutoRevoke = *file.Security.ExposureAutoRevoke
		}
		if v := strings.TrimSpace(file.Security.ExposureWebhookURL); v != "" {
			cfg.ExposureWebhookURL = v
		}
		if v := strings.TrimSpace(file.Security.RotationWebhookURL); v != "" {
			cfg.RotationWebhookURL = v
		}
		if file.Security.AllowCoarsePKIWrite != nil {
			cfg.AllowCoarsePKIWrite = *file.Security.AllowCoarsePKIWrite
		}
		if file.Security.AuthOIDCEnabled != nil {
			cfg.AuthOIDCEnabled = *file.Security.AuthOIDCEnabled
		}
		if file.Security.AuthLDAPEnabled != nil {
			cfg.AuthLDAPEnabled = *file.Security.AuthLDAPEnabled
		}
		if file.Security.ACMERelatedEnabled != nil {
			cfg.ACMERelatedEnabled = *file.Security.ACMERelatedEnabled
		}
	}
	if file.Tracing != nil {
		if file.Tracing.Enabled != nil {
			cfg.TracingEnabled = *file.Tracing.Enabled
		}
		if v := strings.TrimSpace(file.Tracing.OTLPEndpoint); v != "" {
			cfg.OTLPEndpoint = v
		}
		if file.Tracing.SampleRatio != nil {
			cfg.TracingSampleRatio = *file.Tracing.SampleRatio
		}
	}
	if file.Raft != nil {
		raft, err := applyRaftFile(cfg.Raft, *file.Raft)
		if err != nil {
			return Config{}, err
		}
		cfg.Raft = raft
	}
	return cfg, nil
}

func applyRaftFile(cfg RaftConfig, file RaftFile) (RaftConfig, error) {
	if file.Enabled != nil {
		cfg.Enabled = *file.Enabled
	}
	if file.NodeID != nil {
		cfg.NodeID = *file.NodeID
	}
	if v := strings.TrimSpace(file.Address); v != "" {
		cfg.RaftAddress = v
	}
	if v := strings.TrimSpace(file.ListenAddress); v != "" {
		cfg.ListenAddress = v
	}
	if v := strings.TrimSpace(file.DataDir); v != "" {
		cfg.DataDir = v
	}
	if v := strings.TrimSpace(file.InitialMembers); v != "" {
		cfg.InitialMembersRaw = v
	}
	if file.ElectionRTT != nil {
		cfg.ElectionRTT = *file.ElectionRTT
	}
	if file.HeartbeatRTT != nil {
		cfg.HeartbeatRTT = *file.HeartbeatRTT
	}
	if file.RTTMillisecond != nil {
		cfg.RTTMillisecond = *file.RTTMillisecond
	}
	if v := strings.TrimSpace(file.LeaderWait); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return RaftConfig{}, fmt.Errorf("raft.leader_wait: %w", err)
		}
		cfg.LeaderWait = d
	}
	if file.Join != nil {
		cfg.Join = *file.Join
	}
	if v := strings.TrimSpace(file.MTLSCert); v != "" {
		cfg.MTLSCertFile = v
	}
	if v := strings.TrimSpace(file.MTLSKey); v != "" {
		cfg.MTLSKeyFile = v
	}
	if v := strings.TrimSpace(file.MTLSCA); v != "" {
		cfg.MTLSCAFile = v
	}
	return cfg, nil
}
