// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme_test

import (
	"os"
	"testing"

	"github.com/kubenexis/knxvault/internal/acme"
)

func TestDoctorProfile(t *testing.T) {
	checks := acme.DoctorProfile(nil)
	if len(checks) == 0 {
		t.Fatal("expected checks")
	}
	p := &acme.Profile{
		DirectoryURL: acme.StagingDirectory,
		Email:        "ops@example.com",
		AcceptTOS:    true,
		AccountKey:   t.TempDir() + "/acct.key",
		HTTP01:       &acme.ProfileHTTP01{Mode: "webroot", Webroot: t.TempDir()},
		Domains:      []acme.ProfileDomain{{Name: "app.example.com"}},
		Delivery: acme.ProfileDelivery{
			Type:     "files",
			CertPath: t.TempDir() + "/c.pem",
			KeyPath:  t.TempDir() + "/k.pem",
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	checks = acme.DoctorProfile(p)
	if len(checks) < 2 {
		t.Fatalf("%v", checks)
	}
}

func TestToConfig(t *testing.T) {
	p := &acme.Profile{
		DirectoryURL: acme.StagingDirectory,
		Email:        "a@b.c",
		AcceptTOS:    true,
		Challenges:   []string{"http-01", "dns-01"},
	}
	cfg := p.ToConfig(nil)
	if !cfg.AcceptTOS || len(cfg.Challenges) != 2 {
		t.Fatalf("%+v", cfg)
	}
}

func TestRunIssueValidate(t *testing.T) {
	_, err := acme.RunIssue(t.Context(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	p := &acme.Profile{AcceptTOS: false, Email: "a@b.c"}
	_, err = acme.RunIssue(t.Context(), p)
	if err == nil {
		t.Fatal("expected validate error")
	}
}

func TestRunRenewNoOp(t *testing.T) {
	dir := t.TempDir()
	state := dir + "/state.json"
	// write future notAfter state
	rec := `{"common_name":"x","cert_path":"` + dir + `/c.pem","key_path":"` + dir + `/k.pem","not_after":"2099-01-01T00:00:00Z"}`
	if err := os.WriteFile(state, []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &acme.Profile{
		DirectoryURL: acme.StagingDirectory,
		Email:        "ops@example.com",
		AcceptTOS:    true,
		AccountKey:   dir + "/acct.key",
		StateFile:    state,
		HTTP01:       &acme.ProfileHTTP01{Mode: "webroot", Webroot: dir},
		Domains:      []acme.ProfileDomain{{Name: "app.example.com"}},
		Delivery:     acme.ProfileDelivery{CertPath: dir + "/c.pem", KeyPath: dir + "/k.pem"},
		RenewBefore:  "720h",
	}
	renewed, _, err := acme.RunRenew(t.Context(), p)
	if err != nil || renewed {
		t.Fatalf("renewed=%v err=%v", renewed, err)
	}
}

func TestBuildSolversDNSMemory(t *testing.T) {
	p := &acme.Profile{
		DirectoryURL: acme.StagingDirectory,
		Email:        "ops@example.com",
		AcceptTOS:    true,
		DNS01:        &acme.ProfileDNS01{Provider: "memory"},
		Domains:      []acme.ProfileDomain{{Name: "app.example.com"}},
		Delivery:     acme.ProfileDelivery{CertPath: "/c", KeyPath: "/k"},
	}
	http01, dns01, mem, err := acme.BuildSolversFromProfile(p)
	if err != nil || http01 != nil || dns01 == nil || mem != nil {
		t.Fatalf("%v %v %v %v", http01, dns01, mem, err)
	}
}

func TestBuildSolversListenMode(t *testing.T) {
	p := &acme.Profile{
		HTTP01: &acme.ProfileHTTP01{Mode: "listen", ListenAddr: "127.0.0.1:0"},
	}
	http01, _, mem, err := acme.BuildSolversFromProfile(p)
	if err != nil || http01 == nil || mem == nil {
		t.Fatalf("%v %v %v", http01, mem, err)
	}
}

func TestRunRenewNil(t *testing.T) {
	_, _, err := acme.RunRenew(t.Context(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
}
