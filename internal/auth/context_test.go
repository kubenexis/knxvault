// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestResolveTenantNamespaceRejectsSASpoofing(t *testing.T) {
	_, err := auth.ResolveTenantNamespace("staging", "system:serviceaccount:prod:app")
	if err == nil {
		t.Fatal("expected namespace mismatch error for SA token")
	}
	got, err := auth.ResolveTenantNamespace("prod", "system:serviceaccount:prod:app")
	if err != nil || got != "prod" {
		t.Fatalf("matching header: ns=%q err=%v", got, err)
	}
}

func TestRequestNamespaceHeaderWinsForNonSA(t *testing.T) {
	got := auth.RequestNamespace("staging", "ci-bot")
	if got != "staging" {
		t.Fatalf("namespace = %q, want staging", got)
	}
}

func TestRequestNamespaceFromServiceAccountSubject(t *testing.T) {
	got := auth.RequestNamespace("", "system:serviceaccount:prod:app")
	if got != "prod" {
		t.Fatalf("namespace = %q, want prod", got)
	}
}

func TestRequestNamespaceEmpty(t *testing.T) {
	if auth.RequestNamespace("", "ci-bot") != "" {
		t.Fatal("expected empty namespace for non-SA subject")
	}
}
