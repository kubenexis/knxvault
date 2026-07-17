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
		UnsealAllowCIDRs:    []string{"10.0.0.0/8"},
	}
}

func TestW80_ProductionRejectsBroadUnsealCIDR(t *testing.T) {
	cfg := baseProdW80()
	cfg.UnsealAllowCIDRs = []string{"0.0.0.0/1"}
	if err := config.ValidateSecurity(cfg, ""); err == nil || !strings.Contains(err.Error(), "too broad") {
		t.Fatalf("want broad CIDR error, got %v", err)
	}
	cfg.UnsealAllowCIDRs = []string{"10.0.0.0/7"}
	if err := config.ValidateSecurity(cfg, ""); err == nil || !strings.Contains(err.Error(), "too broad") {
		t.Fatalf("want /7 error, got %v", err)
	}
	cfg.UnsealAllowCIDRs = []string{"10.0.0.0/8", "192.168.0.0/16"}
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatalf("expected OK for /8 and /16: %v", err)
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

func TestW80_LabKeepsCoarsePKIWrite(t *testing.T) {
	cfg := config.Config{SecurityProfile: config.SecurityProfileLab, AllowCoarsePKIWrite: true}
	if err := config.ApplySecurityProfileDefaults(&cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowCoarsePKIWrite {
		t.Fatal("lab should keep coarse PKI write enabled by default path")
	}
}
