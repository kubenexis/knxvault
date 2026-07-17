// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/config"
)

func TestFeatureGatesDefaults(t *testing.T) {
	t.Setenv("KNXVAULT_MASTER_KEY", "") // ensure clean
	// Clear any gate env from parent.
	for _, k := range []string{
		"KNXVAULT_AUTH_OIDC_ENABLED",
		"KNXVAULT_AUTH_LDAP_ENABLED",
		"KNXVAULT_AUDIT_FORWARD_ENABLED",
		"KNXVAULT_ACME_RELATED_ENABLED",
	} {
		t.Setenv(k, "")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.AuthOIDCEnabled || !cfg.AuthLDAPEnabled {
		t.Fatalf("lab defaults: OIDC/LDAP should be true, got oidc=%v ldap=%v", cfg.AuthOIDCEnabled, cfg.AuthLDAPEnabled)
	}
	if cfg.AuditForwardEnabled {
		t.Fatal("audit forward should default false")
	}
	if !cfg.ACMERelatedEnabled {
		t.Fatal("ACME related should default true in lab")
	}
}

func TestFeatureGatesFromEnv(t *testing.T) {
	t.Setenv("KNXVAULT_AUTH_OIDC_ENABLED", "false")
	t.Setenv("KNXVAULT_AUTH_LDAP_ENABLED", "false")
	t.Setenv("KNXVAULT_AUDIT_FORWARD_ENABLED", "true")
	t.Setenv("KNXVAULT_ACME_RELATED_ENABLED", "false")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AuthOIDCEnabled || cfg.AuthLDAPEnabled {
		t.Fatalf("expected OIDC/LDAP disabled, got oidc=%v ldap=%v", cfg.AuthOIDCEnabled, cfg.AuthLDAPEnabled)
	}
	if !cfg.AuditForwardEnabled {
		t.Fatal("expected audit forward enabled")
	}
	if cfg.ACMERelatedEnabled {
		t.Fatal("expected ACME related disabled")
	}
}

func TestFeatureGatesInvalidBool(t *testing.T) {
	t.Setenv("KNXVAULT_AUTH_OIDC_ENABLED", "not-a-bool")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for invalid OIDC gate")
	}
}
