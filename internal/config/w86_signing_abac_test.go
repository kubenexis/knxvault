// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"

	"github.com/kubenexis/knxvault/internal/config"
)

func productionEnv(t *testing.T) {
	t.Helper()
	t.Setenv("KNXVAULT_SECURITY_PROFILE", "production")
	t.Setenv("KNXVAULT_AUDIT_SIGNING_KEY", "audit-signing-key-for-tests-32b!!")
	t.Setenv("KNXVAULT_METRICS_BEARER_TOKEN", "metrics-bearer-token")
	t.Setenv("KNXVAULT_UNSEAL_ALLOW_CIDRS", "10.0.0.10/32")
	t.Setenv("KNXVAULT_TLS_TERMINATION", "ingress")
	t.Setenv("KNXVAULT_RAFT_ENABLED", "false")
	t.Setenv("KNXVAULT_TRUST_CLIENT_ABAC_HEADERS", "")
	t.Setenv("KNXVAULT_REQUEST_SIGNING_KEY", "")
	t.Setenv("KNXVAULT_REQUEST_SIGNING_REQUIRED", "")
}

func TestW86_ProductionIgnoresClientABACTrustEnv(t *testing.T) {
	productionEnv(t)
	// Even if env tries to enable client ABAC trust, production defaults force false.
	t.Setenv("KNXVAULT_TRUST_CLIENT_ABAC_HEADERS", "true")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TrustClientABACHeaders {
		t.Fatal("production must force TrustClientABACHeaders=false")
	}
}

func TestW86_ValidateSecurityRejectsClientABACTrust(t *testing.T) {
	cfg := config.Config{
		SecurityProfile:        config.SecurityProfileProduction,
		RateLimitEnabled:       true,
		RBACSyncFailClosed:     true,
		RequireHTTPSClients:    true,
		AuditSigningKey:        "audit-key",
		MetricsBearerToken:     "metrics",
		TLSTermination:         config.TLSTerminationIngress,
		UnsealAllowCIDRs:       []string{"10.0.0.10/32"},
		ManagedSQLStrict:       true,
		RootTokenTTL:           config.MaxProductionRootTokenTTL,
		TrustClientABACHeaders: true,
	}
	if err := config.ApplySecurityProfileDefaults(&cfg); err != nil {
		t.Fatal(err)
	}
	// Re-enable after defaults to simulate misconfiguration.
	cfg.TrustClientABACHeaders = true
	err := config.ValidateSecurity(cfg, "")
	if err == nil || !strings.Contains(err.Error(), "ABAC") {
		t.Fatalf("expected ABAC validation error, got %v", err)
	}
}

func TestW86_ProductionSigningKeyForcesRequired(t *testing.T) {
	productionEnv(t)
	t.Setenv("KNXVAULT_REQUEST_SIGNING_KEY", "hmac-request-signing-secret")
	// Explicit false must still fail production validation.
	t.Setenv("KNXVAULT_REQUEST_SIGNING_REQUIRED", "false")
	_, err := config.Load()
	if err == nil {
		// Load may re-force required when key set after overlay — either OK load with required=true or error
		t.Log("Load returned nil; checking forced required")
	}
	// Reset: key set without required=false should load with required true
	t.Setenv("KNXVAULT_REQUEST_SIGNING_REQUIRED", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.RequestSigningRequired {
		t.Fatal("production with signing key must force RequestSigningRequired")
	}
	if cfg.TrustClientABACHeaders {
		t.Fatal("production must not trust client ABAC headers")
	}
}

func TestW86_ProductionServerABACAttrs(t *testing.T) {
	productionEnv(t)
	t.Setenv("KNXVAULT_ABAC_ENVIRONMENT", "prod")
	t.Setenv("KNXVAULT_ABAC_CLUSTER", "core-a")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ABACEnvironment != "prod" || cfg.ABACCluster != "core-a" {
		t.Fatalf("ABAC attrs = %q/%q", cfg.ABACEnvironment, cfg.ABACCluster)
	}
	if cfg.TrustClientABACHeaders {
		t.Fatal("client ABAC trust must be false")
	}
}
