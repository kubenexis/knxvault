// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/config"
)

func TestProductionProfileFailClosedFeatureGates(t *testing.T) {
	// Bare production without gate env → OIDC/LDAP off.
	t.Setenv("KNXVAULT_SECURITY_PROFILE", "production")
	t.Setenv("KNXVAULT_AUTH_OIDC_ENABLED", "")
	t.Setenv("KNXVAULT_AUTH_LDAP_ENABLED", "")
	t.Setenv("KNXVAULT_AUDIT_FORWARD_ENABLED", "")
	t.Setenv("KNXVAULT_ACME_RELATED_ENABLED", "")
	// Minimal production secrets for ValidateSecurity
	t.Setenv("KNXVAULT_AUDIT_SIGNING_KEY", "audit-signing-key-for-tests-32b!!")
	t.Setenv("KNXVAULT_METRICS_BEARER_TOKEN", "metrics-bearer-token")
	t.Setenv("KNXVAULT_UNSEAL_ALLOW_CIDRS", "10.0.0.10/32")
	t.Setenv("KNXVAULT_TLS_TERMINATION", "ingress")
	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AuthOIDCEnabled || cfg.AuthLDAPEnabled || cfg.AuditForwardEnabled || cfg.ACMERelatedEnabled {
		t.Fatalf("production bare gates want all false, got oidc=%v ldap=%v audit=%v acme=%v",
			cfg.AuthOIDCEnabled, cfg.AuthLDAPEnabled, cfg.AuditForwardEnabled, cfg.ACMERelatedEnabled)
	}
}

func TestProductionProfileEdgeCanReenableOIDC(t *testing.T) {
	t.Setenv("KNXVAULT_SECURITY_PROFILE", "production")
	t.Setenv("KNXVAULT_AUTH_OIDC_ENABLED", "true")
	t.Setenv("KNXVAULT_AUTH_LDAP_ENABLED", "false")
	t.Setenv("KNXVAULT_AUDIT_SIGNING_KEY", "audit-signing-key-for-tests-32b!!")
	t.Setenv("KNXVAULT_METRICS_BEARER_TOKEN", "metrics-bearer-token")
	t.Setenv("KNXVAULT_UNSEAL_ALLOW_CIDRS", "10.0.0.10/32")
	t.Setenv("KNXVAULT_TLS_TERMINATION", "ingress")
	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.AuthOIDCEnabled {
		t.Fatal("edge overlay must re-enable OIDC via env after production defaults")
	}
	if cfg.AuthLDAPEnabled {
		t.Fatal("LDAP should stay false")
	}
}
