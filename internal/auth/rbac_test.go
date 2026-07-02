package auth_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestRBACAuthorize(t *testing.T) {
	rbac := auth.NewRBAC()
	req := auth.RequestContext{}
	if !rbac.Authorize([]string{"secrets-reader"}, "secrets/kv/app", "read", req) {
		t.Fatal("expected secrets read to be allowed")
	}
	if rbac.Authorize([]string{"secrets-reader"}, "secrets/kv/app", "write", req) {
		t.Fatal("expected secrets write to be denied")
	}
	if !rbac.Authorize([]string{"admin"}, "pki/root", "write", req) {
		t.Fatal("expected admin to be allowed")
	}
}

func TestCapabilitiesIncludesCapabilityField(t *testing.T) {
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name:         "cap-only",
		Effect:       domainauth.EffectAllow,
		Resources:    []string{"secrets/kv/*"},
		Capabilities: []string{"read"},
	})
	caps := rbac.Capabilities([]string{"cap-only"})
	if len(caps) != 1 || caps[0] != "secrets/kv/*:read" {
		t.Fatalf("Capabilities() = %v", caps)
	}
}

func TestDenyOverridesAllow(t *testing.T) {
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name: "team-a-allow", Effect: domainauth.EffectAllow,
		Resources: []string{"secrets/kv/team-a/*"}, Actions: []string{"read"},
	})
	rbac.UpsertPolicy(domainauth.Policy{
		Name: "team-a-deny", Effect: domainauth.EffectDeny,
		Resources: []string{"secrets/kv/team-a/*"}, Actions: []string{"read"},
	})
	req := auth.RequestContext{}
	if rbac.Authorize([]string{"team-a-allow", "team-a-deny"}, "secrets/kv/team-a/x", "read", req) {
		t.Fatal("deny should override allow")
	}
}

func TestGlobResourceMatch(t *testing.T) {
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name: "glob-read", Effect: domainauth.EffectAllow,
		Resources: []string{"secrets/kv/team-?/app-*"}, Actions: []string{"read"},
	})
	req := auth.RequestContext{}
	if !rbac.Authorize([]string{"glob-read"}, "secrets/kv/team-a/app-config", "read", req) {
		t.Fatal("expected glob match")
	}
	if rbac.Authorize([]string{"glob-read"}, "secrets/kv/team-b/other", "read", req) {
		t.Fatal("expected glob deny")
	}
}
