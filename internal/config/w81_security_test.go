// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/config"
)

func TestW81_ProductionRequiresTokenAudiencesWithRaft(t *testing.T) {
	cfg := productionBase()
	cfg.UnsealKey = "dGVzdC11bnNlYWwta2V5MTIzNDU2Nzg5MDEyMzQ1Ng=="
	cfg.Raft = config.RaftConfig{
		Enabled:           true,
		InitialMembersRaw: "1=a:1",
		MTLSCertFile:      "c",
		MTLSKeyFile:       "k",
		MTLSCAFile:        "ca",
	}
	cfg.K8sTokenAudiences = nil
	_ = config.ApplySecurityProfileDefaults(&cfg)
	err := config.ValidateSecurity(cfg, "")
	if err == nil || !strings.Contains(err.Error(), "TOKEN_AUDIENCES") {
		t.Fatalf("want audiences error, got %v", err)
	}
	cfg.K8sTokenAudiences = []string{"knxvault"}
	if err := config.ValidateSecurity(cfg, ""); err != nil {
		t.Fatal(err)
	}
}

func TestW81_ProductionRejectsLabUnsealEqualsMaster(t *testing.T) {
	cfg := productionBase()
	cfg.LabUnsealEqualsMaster = true
	_ = config.ApplySecurityProfileDefaults(&cfg)
	if cfg.LabUnsealEqualsMaster {
		t.Fatal("production must clear LabUnsealEqualsMaster")
	}
}

func TestW81_ProductionRejectsIPv4UnsealBroaderThan16(t *testing.T) {
	cfg := productionBase()
	cfg.UnsealAllowCIDRs = []string{"10.0.0.0/15"}
	if err := config.ValidateSecurity(cfg, ""); err == nil || !strings.Contains(err.Error(), "too broad") {
		t.Fatalf("want too broad, got %v", err)
	}
}

func TestW81_ProductionRootTTLStillCapped(t *testing.T) {
	cfg := productionBase()
	cfg.RootTokenTTL = 72 * time.Hour
	_ = config.ApplySecurityProfileDefaults(&cfg)
	if cfg.RootTokenTTL > config.MaxProductionRootTokenTTL {
		t.Fatalf("ttl=%v", cfg.RootTokenTTL)
	}
}
