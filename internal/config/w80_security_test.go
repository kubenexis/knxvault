// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/config"
)

func baseProdW80() config.Config {
	return config.Config{
		SecurityProfile:     config.SecurityProfileProduction,
		RateLimitEnabled:    true,
		RBACSyncFailClosed:  true,
		RequireHTTPSClients: true,
		ManagedSQLStrict:    true,
		AllowCoarsePKIWrite: false,
		AuditSigningKey:     "audit-key",
		MetricsBearerToken:  "metrics-tok",
		RootTokenTTL:        time.Hour,
		TLSTermination:      config.TLSTerminationIngress,
		UnsealAllowCIDRs:    []string{"10.0.0.0/16"},
	}
}

func TestW80_ProductionRejectsBroadUnsealCIDR(t *testing.T) {
	cfg := baseProdW80()
	cfg.UnsealAllowCIDRs = []string{"0.0.0.0/1"}
	if err := config.ValidateSecurity(cfg, ""); err == nil || !strings.Contains(err.Error(), "too broad") {
		t.Fatalf("want broad CIDR error, got %v", err)
	}
	cfg.UnsealAllowCIDRs = []string{"10.0.0.0/8"}
	if err := config.ValidateSecurity(cfg, ""); err == nil || !strings.Contains(err.Error(), "too broad") {
		t.Fatalf("want /7 error, got %v", err)
	}
	cfg.UnsealAllowCIDRs = []string{"10.0.0.0/16", "192.168.0.0/16"}
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("expected OK for /16: %v", err)
	}
}

func TestW80_ProductionDisablesCoarsePKIWrite(t *testing.T) {
	cfg := baseProdW80()
	cfg.AllowCoarsePKIWrite = true
	if err := config.ApplySecurityProfileDefaults(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.AllowCoarsePKIWrite {
		t.Fatal("production must force AllowCoarsePKIWrite=false")
	}
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatal(err)
	}
	// Explicit re-enable after defaults must still fail validation.
	cfg.AllowCoarsePKIWrite = true
	if err := config.ValidateSecurity(cfg, ""); err == nil || !strings.Contains(err.Error(), "coarse PKI") {
		t.Fatalf("want coarse PKI error, got %v", err)
	}
}

func TestW80_LabCoarsePKIWriteOptIn(t *testing.T) {
	cfg := config.Config{SecurityProfile: config.SecurityProfileLab, AllowCoarsePKIWrite: true}
	if err := config.ApplySecurityProfileDefaults(&cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowCoarsePKIWrite {
		t.Fatal("lab should allow explicit coarse PKI write opt-in")
	}
	cfg2 := config.Config{SecurityProfile: config.SecurityProfileLab}
	_ = config.ApplySecurityProfileDefaults(&cfg2)
	// Zero value remains false after defaults (W81: coarse off by default).
	if cfg2.AllowCoarsePKIWrite {
		t.Fatal("lab default AllowCoarsePKIWrite should be false without opt-in")
	}
}
