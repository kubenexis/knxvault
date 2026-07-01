package auth_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/auth"
)

func TestRequestNamespaceHeaderWins(t *testing.T) {
	got := auth.RequestNamespace("staging", "system:serviceaccount:prod:app")
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
