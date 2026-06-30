package pki

import (
	"fmt"
	"strings"
)

// RoleUsage describes allowed certificate key usage for a PKI role.
type RoleUsage string

const (
	RoleUsageServer      RoleUsage = "server"
	RoleUsageClient      RoleUsage = "client"
	RoleUsageCodeSigning RoleUsage = "code_signing"
)

// Role is a persisted PKI issuance policy (LLD §4.A.3).
type Role struct {
	Name            string
	CAName          string
	AllowedDomains  []string
	MaxTTLSeconds   int
	KeyUsage        RoleUsage
	AllowSubdomains bool
}

// Validate checks required PKI role fields.
func (r *Role) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("pki role name is required")
	}
	if r.CAName == "" {
		return fmt.Errorf("pki role ca_name is required")
	}
	switch r.KeyUsage {
	case "", RoleUsageServer, RoleUsageClient, RoleUsageCodeSigning:
	default:
		return fmt.Errorf("invalid pki role key_usage %q", r.KeyUsage)
	}
	if r.KeyUsage == "" {
		r.KeyUsage = RoleUsageServer
	}
	return nil
}

// AllowedDomain matches a DNS SAN against role policy.
func (r *Role) AllowedDomain(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	for _, allowed := range r.AllowedDomains {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == "" {
			continue
		}
		if allowed == name {
			return true
		}
		if r.AllowSubdomains && strings.HasSuffix(name, "."+allowed) {
			return true
		}
	}
	return len(r.AllowedDomains) == 0
}