// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

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
	// W52-02: default-deny — require at least one allowed domain or explicit "*".
	if len(normalizeAllowedDomains(r.AllowedDomains)) == 0 {
		return fmt.Errorf("pki role allowed_domains is required (use \"*\" only when unconstrained issuance is intentional)")
	}
	return nil
}

func normalizeAllowedDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// AllowsAnyDomain reports whether the role explicitly allows all DNS names ("*").
func (r *Role) AllowsAnyDomain() bool {
	if r == nil {
		return false
	}
	for _, allowed := range r.AllowedDomains {
		if strings.TrimSpace(allowed) == "*" {
			return true
		}
	}
	return false
}

// AllowedDomain matches a DNS SAN against role policy.
// Empty AllowedDomains denies all names (W52-02). Use "*" for unconstrained roles.
func (r *Role) AllowedDomain(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	if r.AllowsAnyDomain() {
		return true
	}
	for _, allowed := range r.AllowedDomains {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == "" || allowed == "*" {
			continue
		}
		if allowed == name {
			return true
		}
		if r.AllowSubdomains && strings.HasSuffix(name, "."+allowed) {
			return true
		}
	}
	return false
}
