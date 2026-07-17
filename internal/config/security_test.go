package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/config"
)

func TestValidateSecurityRejectsInsecureK8sWithRaft(t *testing.T) {
	cfg := config.Config{
		SecurityProfile: config.SecurityProfileLab,
		Raft:            config.RaftConfig{Enabled: true},
		K8sAuthInsecure: true,
		UnsealKey:       "dGVzdA==",
	}
	if err := config.ValidateSecurity(cfg, ""); err == nil {
		t.Fatal("expected error for insecure k8s auth with raft")
	}
}

func TestValidateSecurityRejectsInsecureK8sWithoutLabFlag(t *testing.T) {
	cfg := config.Config{SecurityProfile: config.SecurityProfileLab, K8sAuthInsecure: true}
	if err := config.ValidateSecurity(cfg, ""); err == nil {
		t.Fatal("expected k8s_auth_insecure without lab flag to fail")
	}
	cfg.RaftAllowInsecure = true
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("lab escape: %v", err)
	}
}

func TestValidateSecurityRejectsWorldReadableConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "knxvault.conf")
	if err := os.WriteFile(path, []byte("http_addr: :8200\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg := config.Config{SecurityProfile: config.SecurityProfileLab}
	if err := config.ValidateSecurity(cfg, path); err == nil {
		t.Fatal("expected permission error for world-readable config")
	}
}

func TestValidateSecurityRequiresRaftMTLSForMultiNode(t *testing.T) {
	cfg := config.Config{
		SecurityProfile: config.SecurityProfileLab,
		Raft: config.RaftConfig{
			Enabled: true,
			InitialMembers: map[uint64]string{
				1: "127.0.0.1:63001",
				2: "127.0.0.1:63002",
			},
		},
		UnsealKey: "dGVzdA==",
	}
	if err := config.ValidateSecurity(cfg, ""); err == nil {
		t.Fatal("expected raft mTLS required")
	}
	cfg.RaftAllowInsecure = true
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("allow insecure: %v", err)
	}
	cfg.RaftAllowInsecure = false
	cfg.Raft.MTLSCertFile = "c"
	cfg.Raft.MTLSKeyFile = "k"
	cfg.Raft.MTLSCAFile = "ca"
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("with mTLS: %v", err)
	}
}

func TestValidateSecurityMultiNodeFromInitialMembersRaw(t *testing.T) {
	cfg := config.Config{
		SecurityProfile: config.SecurityProfileLab,
		UnsealKey:       "dGVzdA==",
		Raft: config.RaftConfig{
			Enabled:           true,
			InitialMembersRaw: "1=a:1,2=b:1,3=c:1",
		},
	}
	if err := config.ValidateSecurity(cfg, ""); err == nil {
		t.Fatal("expected multi-node raw members to require mTLS")
	}
	cfg.Raft.MTLSCertFile = "c"
	cfg.Raft.MTLSKeyFile = "k"
	cfg.Raft.MTLSCAFile = "ca"
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("with mTLS: %v", err)
	}
}

func productionBase() config.Config {
	return config.Config{
		SecurityProfile:     config.SecurityProfileProduction,
		TLSTermination:      config.TLSTerminationServer,
		TLSCertFile:         "/etc/knxvault/tls/server.pem",
		TLSKeyFile:          "/etc/knxvault/tls/server.key",
		AuditSigningKey:     "audit-hmac-key",
		MetricsBearerToken:  "metrics-token",
		RateLimitEnabled:    true,
		RBACSyncFailClosed:  true,
		RequireHTTPSClients: true,
		RootTokenTTL:        4 * time.Hour,
	}
}

func TestProductionProfileAcceptsValidConfig(t *testing.T) {
	cfg := productionBase()
	if err := config.ApplySecurityProfileDefaults(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("valid production: %v", err)
	}
	if cfg.RootTokenTTL != config.MaxProductionRootTokenTTL {
		t.Fatalf("RootTokenTTL = %v", cfg.RootTokenTTL)
	}
}

func TestProductionProfileRejectsMissingTLS(t *testing.T) {
	cfg := productionBase()
	cfg.TLSCertFile = ""
	cfg.TLSKeyFile = ""
	_ = config.ApplySecurityProfileDefaults(&cfg)
	err := config.ValidateSecurity(cfg, "")
	if err == nil || !strings.Contains(err.Error(), "server TLS") {
		t.Fatalf("want TLS error, got %v", err)
	}
}

func TestProductionProfileAllowsIngressTLSTermination(t *testing.T) {
	cfg := productionBase()
	cfg.TLSCertFile = ""
	cfg.TLSKeyFile = ""
	cfg.TLSTermination = config.TLSTerminationIngress
	_ = config.ApplySecurityProfileDefaults(&cfg)
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("ingress termination: %v", err)
	}
}

func TestProductionProfileRejectsLabEscapes(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*config.Config)
		want string
	}{
		{"jwt", func(c *config.Config) { c.JWTSecret = "dev" }, "jwt_secret"},
		{"k8s_insecure", func(c *config.Config) { c.K8sAuthInsecure = true; c.RaftAllowInsecure = true }, "k8s_auth_insecure"},
		{"raft_insecure", func(c *config.Config) { c.RaftAllowInsecure = true }, "RAFT_ALLOW_INSECURE"},
		{"no_audit", func(c *config.Config) { c.AuditSigningKey = "" }, "audit signing"},
		{"no_metrics", func(c *config.Config) { c.MetricsBearerToken = "" }, "metrics bearer"},
		{"valkey_plain", func(c *config.Config) { c.ValkeyCacheURL = "redis://cache:6379/0" }, "valkey"},
		{"ldap_insecure", func(c *config.Config) { c.LDAPInsecureSkipVerify = true }, "LDAP"},
		{"ldap_plain", func(c *config.Config) { c.LDAPURL = "ldap://ldap.example.com" }, "ldaps"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := productionBase()
			tc.mut(&cfg)
			_ = config.ApplySecurityProfileDefaults(&cfg)
			err := config.ValidateSecurity(cfg, "")
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) &&
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q should mention %q", err.Error(), tc.want)
			}
		})
	}
}

func TestProductionProfileAcceptsSecureValkey(t *testing.T) {
	for _, u := range []string{
		"rediss://cache:6379/0",
		"redis://user:pass@cache:6379/0",
		"valkeys://cache:6379",
	} {
		cfg := productionBase()
		cfg.ValkeyCacheURL = u
		_ = config.ApplySecurityProfileDefaults(&cfg)
		if err := config.ValidateSecurity(cfg, ""); err != nil {
			t.Fatalf("url %s: %v", u, err)
		}
	}
}

func TestProductionProfileCapsRootTTL(t *testing.T) {
	cfg := productionBase()
	cfg.RootTokenTTL = 72 * time.Hour
	if err := config.ApplySecurityProfileDefaults(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.RootTokenTTL != config.MaxProductionRootTokenTTL {
		t.Fatalf("capped RootTokenTTL = %v, want %v", cfg.RootTokenTTL, config.MaxProductionRootTokenTTL)
	}
}

func TestProductionProfileRejectsMultiNodeRaftWithoutMTLS(t *testing.T) {
	cfg := productionBase()
	cfg.UnsealKey = "dGVzdA=="
	cfg.Raft = config.RaftConfig{
		Enabled:           true,
		InitialMembersRaw: "1=a:1,2=b:1",
	}
	_ = config.ApplySecurityProfileDefaults(&cfg)
	err := config.ValidateSecurity(cfg, "")
	if err == nil || !strings.Contains(err.Error(), "raft mTLS") {
		t.Fatalf("want raft mTLS error, got %v", err)
	}
}

func TestLoadProductionProfileFromEnv(t *testing.T) {
	t.Setenv("KNXVAULT_SECURITY_PROFILE", "production")
	t.Setenv("KNXVAULT_TLS_CERT", "/certs/tls.crt")
	t.Setenv("KNXVAULT_TLS_KEY", "/certs/tls.key")
	t.Setenv("KNXVAULT_AUDIT_SIGNING_KEY", "sign")
	t.Setenv("KNXVAULT_METRICS_BEARER_TOKEN", "m")
	// clear lab-ish vars
	t.Setenv("KNXVAULT_JWT_SECRET", "")
	t.Setenv("KNXVAULT_K8S_AUTH_INSECURE", "")
	t.Setenv("KNXVAULT_RAFT_ALLOW_INSECURE", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load production: %v", err)
	}
	if cfg.SecurityProfile != config.SecurityProfileProduction {
		t.Fatalf("profile = %q", cfg.SecurityProfile)
	}
	if cfg.RootTokenTTL != config.MaxProductionRootTokenTTL {
		t.Fatalf("RootTokenTTL = %v", cfg.RootTokenTTL)
	}
	if !cfg.RateLimitEnabled {
		t.Fatal("rate limit should be forced on")
	}
}

func TestLoadProductionProfileFailsWithoutMetrics(t *testing.T) {
	t.Setenv("KNXVAULT_SECURITY_PROFILE", "production")
	t.Setenv("KNXVAULT_TLS_CERT", "/certs/tls.crt")
	t.Setenv("KNXVAULT_TLS_KEY", "/certs/tls.key")
	t.Setenv("KNXVAULT_AUDIT_SIGNING_KEY", "sign")
	t.Setenv("KNXVAULT_METRICS_BEARER_TOKEN", "")
	t.Setenv("KNXVAULT_JWT_SECRET", "")

	if _, err := config.Load(); err == nil {
		t.Fatal("expected failure without metrics bearer")
	}
}

func TestLoadFileProductionProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prod.yaml")
	content := `---
security:
  profile: production
  tls_termination: ingress
  metrics_bearer_token: from-file
audit:
  signing_key: from-file-audit
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KNXVAULT_SECURITY_PROFILE", "")
	t.Setenv("KNXVAULT_JWT_SECRET", "")
	t.Setenv("KNXVAULT_METRICS_BEARER_TOKEN", "")
	t.Setenv("KNXVAULT_AUDIT_SIGNING_KEY", "")
	t.Setenv("KNXVAULT_TLS_CERT", "")
	t.Setenv("KNXVAULT_TLS_KEY", "")

	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile production: %v", err)
	}
	if cfg.SecurityProfile != config.SecurityProfileProduction {
		t.Fatalf("profile = %q", cfg.SecurityProfile)
	}
	if cfg.TLSTermination != config.TLSTerminationIngress {
		t.Fatalf("tls_termination = %q", cfg.TLSTermination)
	}
	if cfg.MetricsBearerToken != "from-file" {
		t.Fatalf("metrics = %q", cfg.MetricsBearerToken)
	}
}

func TestNormalizeSecurityProfile(t *testing.T) {
	p, err := config.NormalizeSecurityProfile("PROD")
	if err != nil || p != config.SecurityProfileProduction {
		t.Fatalf("got %q %v", p, err)
	}
	if _, err := config.NormalizeSecurityProfile("staging"); err == nil {
		t.Fatal("expected invalid profile error")
	}
}

func TestMultiNodeRaftForcesProductionProfile(t *testing.T) {
	cfg := config.Config{
		SecurityProfile:    config.SecurityProfileLab,
		TLSCertFile:        "/c",
		TLSKeyFile:         "/k",
		AuditSigningKey:    "a",
		MetricsBearerToken: "m",
		UnsealKey:          "dGVzdA==",
		Raft: config.RaftConfig{
			Enabled:           true,
			InitialMembersRaw: "1=a:1,2=b:1,3=c:1",
			MTLSCertFile:      "c",
			MTLSKeyFile:       "k",
			MTLSCAFile:        "ca",
		},
	}
	if err := config.ApplySecurityProfileDefaults(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SecurityProfile != config.SecurityProfileProduction {
		t.Fatalf("profile=%q want production", cfg.SecurityProfile)
	}
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestMultiNodeRaftLabEscapeRequiresAllowInsecure(t *testing.T) {
	cfg := config.Config{
		SecurityProfile:   config.SecurityProfileLab,
		RaftAllowInsecure: true,
		UnsealKey:         "dGVzdA==",
		Raft: config.RaftConfig{
			Enabled:           true,
			InitialMembersRaw: "1=a:1,2=b:1",
		},
	}
	if err := config.ApplySecurityProfileDefaults(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SecurityProfile != config.SecurityProfileLab {
		t.Fatalf("lab escape lost: %q", cfg.SecurityProfile)
	}
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("lab multi-node with allow insecure: %v", err)
	}
}
