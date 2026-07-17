// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/config"
)

func TestW78_ProductionRequiresUnsealCIDRs(t *testing.T) {
	cfg := config.Config{
		SecurityProfile:     config.SecurityProfileProduction,
		TLSTermination:      config.TLSTerminationServer,
		TLSCertFile:         "/c.pem",
		TLSKeyFile:          "/k.pem",
		AuditSigningKey:     "a",
		MetricsBearerToken:  "m",
		RateLimitEnabled:    true,
		RBACSyncFailClosed:  true,
		RequireHTTPSClients: true,
		RootTokenTTL:        4 * time.Hour,
		ManagedSQLStrict:    true,
	}
	_ = config.ApplySecurityProfileDefaults(&cfg)
	err := config.ValidateSecurity(cfg, "")
	if err == nil || !strings.Contains(err.Error(), "unseal allow CIDRs") {
		t.Fatalf("want unseal CIDR error, got %v", err)
	}
	cfg.UnsealAllowCIDRs = []string{"10.0.0.0/8"}
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatal(err)
	}
}
