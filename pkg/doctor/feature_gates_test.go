// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package doctor_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubenexis/knxvault/pkg/client"
	"github.com/kubenexis/knxvault/pkg/doctor"
)

func TestRunnerFeatureGatesProductionDisabledOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "t", "sealed": false})
	}))
	defer srv.Close()
	// Use https scheme for production profile TLS check.
	// httptest is http — production will fail TLS; we still assert feature checks when gates set.
	runner := &doctor.Runner{
		Client: client.New(srv.URL, "tok"),
		Config: doctor.Config{
			Addr:                srv.URL,
			Token:               "tok",
			Profile:             "production",
			AuthOIDCEnabled:     "false",
			AuthLDAPEnabled:     "false",
			AuditForwardEnabled: "false",
			ACMERelatedEnabled:  "false",
		},
	}
	report := runner.Run(context.Background())
	foundOIDC := false
	for _, c := range report.Checks {
		if c.ID == "feature.oidc" && c.Status == doctor.StatusOK {
			foundOIDC = true
		}
	}
	if !foundOIDC {
		t.Fatalf("expected feature.oidc OK when disabled on production: %+v", report.Checks)
	}
}

func TestRunnerFeatureGatesProductionEnabledWarn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "t", "sealed": false})
	}))
	defer srv.Close()
	runner := &doctor.Runner{
		Client: client.New(srv.URL, "tok"),
		Config: doctor.Config{
			Addr:            srv.URL,
			Token:           "tok",
			Profile:         "production",
			AuthOIDCEnabled: "true",
		},
	}
	report := runner.Run(context.Background())
	found := false
	for _, c := range report.Checks {
		if c.ID == "feature.oidc" && c.Status == doctor.StatusWarn {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected feature.oidc WARN when enabled on production: %+v", report.Checks)
	}
}
