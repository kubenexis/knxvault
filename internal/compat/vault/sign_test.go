// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package vault_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/compat/vault"
)

func TestSplitCSV(t *testing.T) {
	if got := vault.SplitCSV(" a.example.com, b.example.com , "); len(got) != 2 || got[0] != "a.example.com" {
		t.Fatalf("SplitCSV = %#v", got)
	}
	if vault.SplitCSV("") != nil {
		t.Fatal("expected nil for empty")
	}
}

func TestSignRequestDNSNames(t *testing.T) {
	req := vault.SignRequest{AltNames: "a.com,b.com", IPSANs: "1.2.3.4", URISANs: "spiffe://x"}
	if len(req.DNSNames()) != 2 {
		t.Fatalf("DNSNames = %v", req.DNSNames())
	}
	if len(req.IPAddresses()) != 1 || req.IPAddresses()[0] != "1.2.3.4" {
		t.Fatalf("IPAddresses = %v", req.IPAddresses())
	}
	if len(req.URIs()) != 1 {
		t.Fatalf("URIs = %v", req.URIs())
	}
}

func TestNewSignSecretResponse(t *testing.T) {
	resp := vault.NewSignSecretResponse(vault.SignResult{
		Certificate: "CERT",
		IssuingCA:   "CA",
		CAChain:     []string{"ROOT", "CA"},
		Serial:      "ab:cd",
		Expiration:  1700000000,
	})
	if resp.Data["certificate"] != "CERT" {
		t.Fatalf("certificate = %v", resp.Data["certificate"])
	}
	if resp.Data["issuing_ca"] != "CA" {
		t.Fatalf("issuing_ca = %v", resp.Data["issuing_ca"])
	}
	chain, ok := resp.Data["ca_chain"].([]any)
	if !ok || len(chain) != 2 {
		t.Fatalf("ca_chain = %T %#v", resp.Data["ca_chain"], resp.Data["ca_chain"])
	}
	if resp.Data["serial_number"] != "ab:cd" {
		t.Fatalf("serial = %v", resp.Data["serial_number"])
	}
	if resp.Data["expiration"] != int64(1700000000) {
		t.Fatalf("expiration = %v", resp.Data["expiration"])
	}
	if resp.RequestID == "" {
		t.Fatal("expected request_id")
	}
}

func TestNewSignSecretResponseIssuingFromChain(t *testing.T) {
	resp := vault.NewSignSecretResponse(vault.SignResult{
		Certificate: "CERT",
		CAChain:     []string{"ROOT", "ISSUER"},
	})
	if resp.Data["issuing_ca"] != "ISSUER" {
		t.Fatalf("issuing_ca = %v", resp.Data["issuing_ca"])
	}
}

func TestExpirationUnix(t *testing.T) {
	if vault.ExpirationUnix(time.Time{}) != 0 {
		t.Fatal("zero time should be 0")
	}
	ts := time.Unix(100, 0).UTC()
	if vault.ExpirationUnix(ts) != 100 {
		t.Fatalf("got %d", vault.ExpirationUnix(ts))
	}
}

func TestParseSignPath(t *testing.T) {
	mount, role := vault.ParseSignPath("pki/sign/web-server")
	if mount != "pki" || role != "web-server" {
		t.Fatalf("got %q %q", mount, role)
	}
	mount, role = vault.ParseSignPath("/v1/pki_int/sign/example-dot-com")
	if mount != "pki_int" || role != "example-dot-com" {
		t.Fatalf("got %q %q", mount, role)
	}
	mount, role = vault.ParseSignPath("not-a-sign-path")
	if mount != "" || role != "" {
		t.Fatalf("expected empty, got %q %q", mount, role)
	}
}

func TestDetectLoginMethod(t *testing.T) {
	if vault.DetectLoginMethod(map[string]any{"role_id": "r", "secret_id": "s"}) != "approle" {
		t.Fatal("expected approle")
	}
	if vault.DetectLoginMethod(map[string]any{"role": "r", "jwt": "j"}) != "kubernetes" {
		t.Fatal("expected kubernetes")
	}
	if vault.DetectLoginMethod(map[string]any{}) != "" {
		t.Fatal("expected empty")
	}
}

func TestNewAuthResponse(t *testing.T) {
	resp := vault.NewAuthResponse("tok", []string{"pki"}, 3600, true)
	if resp.Auth == nil || resp.Auth.ClientToken != "tok" {
		t.Fatalf("auth = %+v", resp.Auth)
	}
	if resp.Auth.LeaseDuration != 3600 || !resp.Auth.Renewable {
		t.Fatalf("lease flags = %+v", resp.Auth)
	}
	if len(resp.Auth.Policies) != 1 {
		t.Fatalf("policies = %v", resp.Auth.Policies)
	}
}
