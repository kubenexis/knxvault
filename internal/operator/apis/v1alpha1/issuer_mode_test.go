// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1_test

import (
	"testing"

	v1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
)

func TestResolveIssuerLegacyVault(t *testing.T) {
	r, err := v1.ResolveIssuerSpec(v1.KNXVaultIssuerSpec{VaultCAName: "web-server"})
	if err != nil || r.Mode != v1.IssuerModeVault || r.VaultCA != "web-server" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestResolveIssuerACME(t *testing.T) {
	r, err := v1.ResolveIssuerSpec(v1.KNXVaultIssuerSpec{
		ACME: &v1.ACMEIssuerSpec{Server: "https://acme.example/dir", HTTP01: true},
	})
	if err != nil || r.Mode != v1.IssuerModeACME || r.ACME == nil {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestResolveIssuerSelfSigned(t *testing.T) {
	r, err := v1.ResolveClusterIssuerSpec(v1.KNXVaultClusterIssuerSpec{
		SelfSigned: &v1.SelfSignedIssuerSpec{TTL: "24h"},
	})
	if err != nil || r.Mode != v1.IssuerModeSelfSigned {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestResolveIssuerConflicts(t *testing.T) {
	_, err := v1.ResolveIssuerSpec(v1.KNXVaultIssuerSpec{
		Vault:      &v1.VaultIssuerSpec{VaultCAName: "a"},
		SelfSigned: &v1.SelfSignedIssuerSpec{},
	})
	if err == nil {
		t.Fatal("expected conflict")
	}
	_, err = v1.ResolveIssuerSpec(v1.KNXVaultIssuerSpec{})
	if err == nil {
		t.Fatal("expected empty error")
	}
}

func TestRejectACMEIfDisabled(t *testing.T) {
	if err := v1.RejectACMEIfDisabled(v1.IssuerModeACME, false); err == nil {
		t.Fatal("expected ErrACMEDisabled")
	}
	if err := v1.RejectACMEIfDisabled(v1.IssuerModeACME, true); err != nil {
		t.Fatalf("enabled should allow ACME: %v", err)
	}
	if err := v1.RejectACMEIfDisabled(v1.IssuerModeVault, false); err != nil {
		t.Fatalf("vault mode should ignore ACME gate: %v", err)
	}
}
