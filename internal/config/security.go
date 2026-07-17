// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// NormalizeSecurityProfile returns lab or production; empty defaults to lab.
func NormalizeSecurityProfile(raw string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(raw))
	switch p {
	case "", SecurityProfileLab:
		return SecurityProfileLab, nil
	case SecurityProfileProduction, "prod":
		return SecurityProfileProduction, nil
	default:
		return "", fmt.Errorf("security profile %q is invalid (want lab or production)", raw)
	}
}

// IsProductionProfile reports whether cfg uses the production security profile.
func IsProductionProfile(cfg Config) bool {
	p, err := NormalizeSecurityProfile(cfg.SecurityProfile)
	return err == nil && p == SecurityProfileProduction
}

// ApplySecurityProfileDefaults mutates cfg for production posture before validation.
// Multi-node Raft forces production unless lab is explicit with RaftAllowInsecure (W75-01 / CIS defaults).
// Call after file + env overlay, before ValidateSecurity.
func ApplySecurityProfileDefaults(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	p, err := NormalizeSecurityProfile(cfg.SecurityProfile)
	if err != nil {
		return err
	}
	cfg.SecurityProfile = p

	// W75-01: multi-node Raft ≈ production. Lab requires explicit RAFT_ALLOW_INSECURE.
	if cfg.Raft.Enabled && raftPeerCount(cfg.Raft) > 1 {
		if cfg.SecurityProfile == SecurityProfileLab && !cfg.RaftAllowInsecure {
			cfg.SecurityProfile = SecurityProfileProduction
		}
	}

	if cfg.SecurityProfile != SecurityProfileProduction {
		return nil
	}
	// Production: rate limit and fail-closed authz are non-optional.
	cfg.RateLimitEnabled = true
	cfg.RBACSyncFailClosed = true
	cfg.RequireHTTPSClients = true
	// Cap bootstrap root lifetime (bootstrap-complete / root death is W62-10).
	if cfg.RootTokenTTL <= 0 || cfg.RootTokenTTL > MaxProductionRootTokenTTL {
		cfg.RootTokenTTL = MaxProductionRootTokenTTL
	}
	term := strings.ToLower(strings.TrimSpace(cfg.TLSTermination))
	switch term {
	case "":
		// Default: expect process TLS unless operator sets ingress.
		cfg.TLSTermination = TLSTerminationServer
	case TLSTerminationIngress, TLSTerminationServer:
		cfg.TLSTermination = term
	default:
		return fmt.Errorf("security.tls_termination %q is invalid (want server or ingress)", cfg.TLSTermination)
	}
	return nil
}

// ValidateSecurity enforces lab baseline + production fail-closed constraints (M-PRODSEC-1 A1).
func ValidateSecurity(cfg Config, configPath string) error {
	if _, err := NormalizeSecurityProfile(cfg.SecurityProfile); err != nil {
		return err
	}

	// W52: insecure K8s JWT parse is lab-only (requires explicit RaftAllowInsecure).
	if cfg.K8sAuthInsecure && !cfg.RaftAllowInsecure {
		return fmt.Errorf("k8s_auth_insecure requires KNXVAULT_RAFT_ALLOW_INSECURE=true (lab only)")
	}
	if cfg.Raft.Enabled {
		if cfg.K8sAuthInsecure {
			return fmt.Errorf("k8s_auth_insecure is not allowed when raft is enabled")
		}
		if cfg.UnsealKey == "" {
			return fmt.Errorf("unseal key is required when raft is enabled (set KNXVAULT_UNSEAL_KEY)")
		}
		if configPath != "" && (cfg.RootToken != "" || cfg.JWTSecret != "") {
			return fmt.Errorf("root_token and jwt_secret must be supplied via environment when raft is enabled, not config file")
		}
		// W50-20 / production: multi-node Raft requires peer mTLS unless explicitly allowed (dev/lab).
		if !cfg.RaftAllowInsecure && raftPeerCount(cfg.Raft) > 1 {
			if cfg.Raft.MTLSCertFile == "" || cfg.Raft.MTLSKeyFile == "" || cfg.Raft.MTLSCAFile == "" {
				return fmt.Errorf("raft mTLS (KNXVAULT_RAFT_MTLS_CERT/KEY/CA) is required for multi-node raft; set KNXVAULT_RAFT_ALLOW_INSECURE=true only for lab")
			}
		}
	}
	if configPath != "" {
		if err := checkConfigFilePermissions(configPath); err != nil {
			return err
		}
	}
	if IsProductionProfile(cfg) {
		if err := validateProductionSecurity(cfg); err != nil {
			return err
		}
	}
	return nil
}

func validateProductionSecurity(cfg Config) error {
	if cfg.K8sAuthInsecure {
		return fmt.Errorf("production profile: k8s_auth_insecure is not allowed")
	}
	if strings.TrimSpace(cfg.JWTSecret) != "" {
		return fmt.Errorf("production profile: jwt_secret / KNXVAULT_JWT_SECRET is lab-only (use TokenReview)")
	}
	if cfg.RaftAllowInsecure {
		return fmt.Errorf("production profile: KNXVAULT_RAFT_ALLOW_INSECURE is not allowed")
	}
	if !cfg.RateLimitEnabled {
		return fmt.Errorf("production profile: rate limiting must be enabled")
	}
	if !cfg.RBACSyncFailClosed {
		return fmt.Errorf("production profile: RBAC sync fail-closed must be enabled")
	}
	if !cfg.RequireHTTPSClients {
		return fmt.Errorf("production profile: require HTTPS clients must be enabled")
	}
	if strings.TrimSpace(cfg.AuditSigningKey) == "" {
		return fmt.Errorf("production profile: audit signing key is required (KNXVAULT_AUDIT_SIGNING_KEY)")
	}
	if strings.TrimSpace(cfg.MetricsBearerToken) == "" {
		return fmt.Errorf("production profile: metrics bearer token is required (KNXVAULT_METRICS_BEARER_TOKEN)")
	}
	if cfg.RootTokenTTL <= 0 || cfg.RootTokenTTL > MaxProductionRootTokenTTL {
		return fmt.Errorf("production profile: root token TTL must be >0 and <= %s (got %s)", MaxProductionRootTokenTTL, cfg.RootTokenTTL)
	}

	term := strings.ToLower(strings.TrimSpace(cfg.TLSTermination))
	switch term {
	case TLSTerminationIngress:
		// Edge terminates TLS; process may listen HTTP on a private network.
	case TLSTerminationServer, "":
		if strings.TrimSpace(cfg.TLSCertFile) == "" || strings.TrimSpace(cfg.TLSKeyFile) == "" {
			return fmt.Errorf("production profile: server TLS required (KNXVAULT_TLS_CERT/KEY) or set KNXVAULT_TLS_TERMINATION=ingress")
		}
	default:
		return fmt.Errorf("production profile: invalid tls_termination %q", cfg.TLSTermination)
	}

	if cfg.Raft.Enabled && raftPeerCount(cfg.Raft) > 1 {
		if cfg.Raft.MTLSCertFile == "" || cfg.Raft.MTLSKeyFile == "" || cfg.Raft.MTLSCAFile == "" {
			return fmt.Errorf("production profile: raft mTLS is required for multi-node raft")
		}
	}

	if err := validateProductionValkeyURL(cfg.ValkeyCacheURL); err != nil {
		return err
	}
	if cfg.MetricsAddr != "" && strings.TrimSpace(cfg.MetricsBearerToken) == "" {
		return fmt.Errorf("production profile: metrics bearer token required when MetricsAddr is set")
	}
	if cfg.AutoUnsealEnabled {
		if strings.ToLower(strings.TrimSpace(cfg.AutoUnsealProvider)) != "aes-kek" {
			return fmt.Errorf("production profile: auto-unseal requires provider aes-kek")
		}
		if cfg.AutoUnsealCiphertext == "" || cfg.AutoUnsealKEK == "" {
			return fmt.Errorf("production profile: auto-unseal requires ciphertext and KEK")
		}
	}
	if cfg.LDAPInsecureSkipVerify {
		return fmt.Errorf("production profile: LDAP insecure skip verify is not allowed")
	}
	if cfg.LDAPURL != "" {
		u := strings.ToLower(strings.TrimSpace(cfg.LDAPURL))
		if strings.HasPrefix(u, "ldap://") && !strings.HasPrefix(u, "ldaps://") {
			// Allow ldap:// only for private lab; production requires ldaps.
			return fmt.Errorf("production profile: LDAP URL must use ldaps://")
		}
	}
	return nil
}

// validateProductionValkeyURL allows empty (no cache). When set, requires TLS (rediss/valkeys)
// or credentials in the URL (userinfo). Plain redis://host without auth is rejected.
func validateProductionValkeyURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("production profile: valkey cache URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "rediss", "valkeys":
		return nil
	case "redis", "valkey":
		if u.User != nil {
			if _, has := u.User.Password(); has || u.User.Username() != "" {
				return nil
			}
		}
		return fmt.Errorf("production profile: valkey/redis URL must use TLS (rediss://) or include credentials")
	case "unix":
		// Local socket — acceptable for co-located Valkey with filesystem isolation.
		return nil
	default:
		return fmt.Errorf("production profile: unsupported valkey URL scheme %q (use rediss:// or redis://user:pass@host)", scheme)
	}
}

// raftPeerCount returns configured Raft peers from the map or InitialMembersRaw.
func raftPeerCount(r RaftConfig) int {
	if len(r.InitialMembers) > 0 {
		return len(r.InitialMembers)
	}
	raw := strings.TrimSpace(r.InitialMembersRaw)
	if raw == "" {
		return 0
	}
	n := 0
	for _, part := range strings.Split(raw, ",") {
		if strings.TrimSpace(part) != "" {
			n++
		}
	}
	return n
}

func checkConfigFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config %s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("config file %s is group- or world-readable; restrict permissions to 0600", path)
	}
	return nil
}

// ProductionRootTokenTTL returns the effective root TTL under production (for docs/tests).
func ProductionRootTokenTTL() time.Duration {
	return MaxProductionRootTokenTTL
}
