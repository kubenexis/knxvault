package auth

import (
	"strings"
	"sync"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

// RBAC evaluates policy names against resource/action pairs.
type RBAC struct {
	mu       sync.RWMutex
	policies map[string]domainauth.Policy
}

// NewRBAC constructs an RBAC engine with default MVP policies.
func NewRBAC() *RBAC {
	defaults := []domainauth.Policy{
		{Name: "admin", Effect: domainauth.EffectAllow, Resources: []string{"*"}, Actions: []string{"*"}},
		{Name: "pki-admin", Effect: domainauth.EffectAllow, Resources: []string{"pki/*"}, Actions: []string{"*"}},
		{Name: "secrets-admin", Effect: domainauth.EffectAllow, Resources: []string{"secrets/*"}, Actions: []string{"*"}},
		{Name: "secrets-reader", Effect: domainauth.EffectAllow, Resources: []string{"secrets/*"}, Actions: []string{"read"}},
		{Name: "audit-reader", Effect: domainauth.EffectAllow, Resources: []string{"audit/*"}, Actions: []string{"read"}},
		{Name: "policy-admin", Effect: domainauth.EffectAllow, Resources: []string{"sys/policies", "sys/roles"}, Actions: []string{"*"}},
		{Name: "inject-reader", Effect: domainauth.EffectAllow, Resources: []string{"inject/*"}, Actions: []string{"read"}},
	}
	policies := make(map[string]domainauth.Policy, len(defaults))
	for _, policy := range defaults {
		policies[policy.Name] = policy
	}
	return &RBAC{policies: policies}
}

// UpsertPolicy stores or replaces a policy.
func (r *RBAC) UpsertPolicy(policy domainauth.Policy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[policy.Name] = policy
}

// DeletePolicy removes a persisted policy.
func (r *RBAC) DeletePolicy(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.policies, name)
}

// LoadPolicies replaces in-memory policies (defaults should be re-applied by caller if needed).
func (r *RBAC) LoadPolicies(policies []domainauth.Policy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies = make(map[string]domainauth.Policy, len(policies))
	for _, policy := range policies {
		r.policies[policy.Name] = policy
	}
}

// Authorize returns true when any assigned policy allows the action.
func (r *RBAC) Authorize(policyNames []string, resource, action string, req RequestContext) bool {
	allowed := false
	for _, name := range policyNames {
		policy, ok := r.policy(name)
		if !ok {
			continue
		}
		if !PolicyMatches(policy, resource, action, req) {
			continue
		}
		if policy.Effect == domainauth.EffectDeny {
			return false
		}
		allowed = true
	}
	return allowed
}

// Capabilities returns allowed action patterns for policy names.
func (r *RBAC) Capabilities(policyNames []string) []string {
	seen := make(map[string]struct{})
	var caps []string
	for _, name := range policyNames {
		policy, ok := r.policy(name)
		if !ok {
			continue
		}
		for _, resource := range policy.Resources {
			for _, action := range policy.Actions {
				cap := resource + ":" + action
				if _, exists := seen[cap]; exists {
					continue
				}
				seen[cap] = struct{}{}
				caps = append(caps, cap)
			}
		}
	}
	return caps
}

func (r *RBAC) policy(name string) (domainauth.Policy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	policy, ok := r.policies[name]
	return policy, ok
}

// RolePolicies maps role names to policy names.
var RolePolicies = map[string][]string{
	"admin":          {"admin"},
	"pki-admin":      {"pki-admin"},
	"secrets-admin":  {"secrets-admin"},
	"secrets-reader": {"secrets-reader"},
	"audit-reader":   {"audit-reader"},
	"policy-admin":   {"policy-admin"},
	"inject-reader":  {"inject-reader"},
	"default":        {"secrets-reader"},
}

// PoliciesForRole returns policy names for a role.
func PoliciesForRole(role string) []string {
	role = strings.TrimSpace(role)
	if policies, ok := RolePolicies[role]; ok {
		return policies
	}
	return RolePolicies["default"]
}
