package auth_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestImportHCLPolicy(t *testing.T) {
	hcl := `
path "secrets/kv/team-a/*" {
  capabilities = ["read", "list"]
}
`
	policies, err := auth.ImportHCLPolicy("team-a", hcl)
	if err != nil {
		t.Fatalf("ImportHCLPolicy() = %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(policies))
	}
	if policies[0].Effect != domainauth.EffectAllow {
		t.Fatalf("effect = %s", policies[0].Effect)
	}
	if policies[0].Resources[0] != "secrets/kv/team-a/*" {
		t.Fatalf("resource = %q", policies[0].Resources[0])
	}
}
