package auth_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestPoliciesFromClaimsGroupMapping(t *testing.T) {
	cfg := &domainauth.OIDCConfig{
		ClaimMappings: []domainauth.ClaimMapping{
			{Claim: "groups", Match: "vault-admins", Policies: []string{"admin"}},
		},
	}
	claims := jwt.MapClaims{"groups": []any{"vault-admins", "other"}}
	policies, err := auth.PoliciesFromClaims(cfg, claims, []string{"default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 || policies[1] != "admin" {
		t.Fatalf("policies = %v", policies)
	}
}

func TestPoliciesFromClaimsForbiddenWithoutMatch(t *testing.T) {
	cfg := &domainauth.OIDCConfig{
		ClaimMappings: []domainauth.ClaimMapping{
			{Claim: "groups", Match: "vault-admins", Policies: []string{"admin"}},
		},
	}
	claims := jwt.MapClaims{"groups": []any{"other"}}
	_, err := auth.PoliciesFromClaims(cfg, claims, []string{"default"})
	if err == nil {
		t.Fatal("expected forbidden")
	}
}
