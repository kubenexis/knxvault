package pki_test

import (
	"testing"

	domainpki "github.com/kubenexis/knxvault/internal/domain/pki"
)

func TestRoleValidateRequiresAllowedDomains(t *testing.T) {
	role := &domainpki.Role{Name: "web", CAName: "root"}
	if err := role.Validate(); err == nil {
		t.Fatal("expected allowed_domains required")
	}
	role.AllowedDomains = []string{"*"}
	if err := role.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAllowedDomainDefaultDeny(t *testing.T) {
	role := &domainpki.Role{Name: "web", CAName: "root", AllowedDomains: nil}
	if role.AllowedDomain("evil.com") {
		t.Fatal("empty domains must deny")
	}
	role.AllowedDomains = []string{"example.com"}
	role.AllowSubdomains = true
	if !role.AllowedDomain("app.example.com") {
		t.Fatal("subdomain should allow")
	}
	if role.AllowedDomain("other.com") {
		t.Fatal("other domain denied")
	}
	role.AllowedDomains = []string{"*"}
	if !role.AllowedDomain("any.example") {
		t.Fatal("* should allow")
	}
}
