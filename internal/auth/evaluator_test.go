package auth_test

import (
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestConditionsMatchIPCIDR(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	policy := domainauth.Policy{
		Name:      "office",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"secrets/*"},
		Actions:   []string{"read"},
		Conditions: map[string]any{
			"ip_cidr": []any{"10.0.0.0/8"},
		},
	}

	if !auth.PolicyMatches(policy, "secrets/kv/app", "read", auth.RequestContext{
		ClientIP: "10.1.2.3",
		Now:      now,
	}) {
		t.Fatal("expected office CIDR to allow")
	}
	if auth.PolicyMatches(policy, "secrets/kv/app", "read", auth.RequestContext{
		ClientIP: "192.168.1.1",
		Now:      now,
	}) {
		t.Fatal("expected outside CIDR to deny")
	}
}

func TestConditionsMatchIPCIDRStringSlice(t *testing.T) {
	policy := domainauth.Policy{
		Name: "office", Effect: domainauth.EffectAllow,
		Resources: []string{"secrets/*"}, Actions: []string{"read"},
		Conditions: map[string]any{
			"ip_cidr": []string{"10.0.0.0/8"},
		},
	}
	if !auth.PolicyMatches(policy, "secrets/kv/app", "read", auth.RequestContext{ClientIP: "10.2.3.4"}) {
		t.Fatal("expected []string ip_cidr to allow")
	}
	if auth.PolicyMatches(policy, "secrets/kv/app", "read", auth.RequestContext{ClientIP: "8.8.8.8"}) {
		t.Fatal("expected []string ip_cidr to deny")
	}
}

func TestConditionsMatchIPCIDRScalarString(t *testing.T) {
	policy := domainauth.Policy{
		Name: "office", Effect: domainauth.EffectAllow,
		Resources: []string{"secrets/*"}, Actions: []string{"read"},
		Conditions: map[string]any{
			"ip_cidr": "10.0.0.0/8",
		},
	}
	if !auth.PolicyMatches(policy, "secrets/kv/app", "read", auth.RequestContext{ClientIP: "10.2.3.4"}) {
		t.Fatal("expected scalar ip_cidr to allow")
	}
	if auth.PolicyMatches(policy, "secrets/kv/app", "read", auth.RequestContext{ClientIP: "8.8.8.8"}) {
		t.Fatal("expected scalar ip_cidr to deny")
	}
}

func TestConditionsMatchNamespace(t *testing.T) {
	policy := domainauth.Policy{
		Name:      "prod-only",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"secrets/kv/*"},
		Actions:   []string{"read"},
		Conditions: map[string]any{
			"namespace": "prod",
		},
	}
	if !auth.PolicyMatches(policy, "secrets/kv/app", "read", auth.RequestContext{Namespace: "prod"}) {
		t.Fatal("expected prod namespace to match")
	}
	if auth.PolicyMatches(policy, "secrets/kv/app", "read", auth.RequestContext{Namespace: "dev"}) {
		t.Fatal("expected dev namespace to fail")
	}
}

func TestConditionsMatchTimeWindow(t *testing.T) {
	policy := domainauth.Policy{
		Name:      "business-hours",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"*"},
		Actions:   []string{"*"},
		Conditions: map[string]any{
			"time_after":  "2026-06-30T09:00:00Z",
			"time_before": "2026-06-30T17:00:00Z",
		},
	}

	inside := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	outside := time.Date(2026, 6, 30, 20, 0, 0, 0, time.UTC)

	if !auth.PolicyMatches(policy, "secrets/kv/x", "read", auth.RequestContext{Now: inside}) {
		t.Fatal("expected inside window to match")
	}
	if auth.PolicyMatches(policy, "secrets/kv/x", "read", auth.RequestContext{Now: outside}) {
		t.Fatal("expected outside window to fail")
	}
}
