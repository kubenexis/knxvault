// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/config"
)

func TestW79_ProductionRejectsWorldOpenUnsealCIDR(t *testing.T) {
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
		UnsealAllowCIDRs:    []string{"0.0.0.0/0"},
	}
	_ = config.ApplySecurityProfileDefaults(&cfg)
	err := config.ValidateSecurity(cfg, "")
	if err == nil || !strings.Contains(err.Error(), "too broad") {
		t.Fatalf("want too broad error, got %v", err)
	}
	cfg.UnsealAllowCIDRs = []string{"10.0.0.0/16"}
	cfg.K8sTokenAudiences = []string{"knxvault"}
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatal(err)
	}
}
