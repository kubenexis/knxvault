// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package operator_test

import (
	"strings"
	"testing"

	"github.com/kubenexis/knxvault/internal/operator"
)

func TestConfigFromEnvDefaultVaultHTTPS(t *testing.T) {
	t.Setenv("KNXVAULT_ADDR", "")
	t.Setenv("KNXVAULT_TOKEN", "")
	t.Setenv("KNXVAULT_OPERATOR_ACME_ENABLED", "")
	cfg := operator.ConfigFromEnv()
	if !strings.HasPrefix(cfg.VaultAddr, "https://") {
		t.Fatalf("VaultAddr default = %q, want https:// (W86-22)", cfg.VaultAddr)
	}
	if cfg.ACMEEnabled {
		t.Fatal("ACMEEnabled should default false")
	}
}

func TestConfigFromEnvACMEFlag(t *testing.T) {
	t.Setenv("KNXVAULT_OPERATOR_ACME_ENABLED", "true")
	cfg := operator.ConfigFromEnv()
	if !cfg.ACMEEnabled {
		t.Fatal("expected ACME enabled when env true")
	}
}
