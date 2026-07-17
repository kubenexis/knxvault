// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

// AuthzResult describes authorization evaluation (W41-04 simulation).
type AuthzResult struct {
	Allowed       bool
	MatchedPolicy string
	Reason        string
	DeniedBy      string
}

// AuthorizeDetailed evaluates policies with deny precedence and returns match metadata.
func (r *RBAC) AuthorizeDetailed(policyNames []string, resource, action string, req RequestContext) AuthzResult {
	allowed := false
	var matchedAllow string
	for _, name := range policyNames {
		policy, ok := r.policy(name)
		if !ok {
			continue
		}
		actions := NormalizeCapabilities(policy.Capabilities, policy.Actions)
		evalPolicy := policy
		evalPolicy.Actions = actions
		if !PolicyMatches(evalPolicy, resource, action, req) {
			continue
		}
		if policy.Effect == domainauth.EffectDeny {
			return AuthzResult{
				Allowed:       false,
				MatchedPolicy: policy.Name,
				DeniedBy:      policy.Name,
				Reason:        "explicit deny",
			}
		}
		allowed = true
		matchedAllow = policy.Name
	}
	if !allowed {
		return AuthzResult{Allowed: false, Reason: "default deny: no matching allow policy"}
	}
	return AuthzResult{Allowed: true, MatchedPolicy: matchedAllow, Reason: "allowed by " + matchedAllow}
}

// ResolvePolicyNames expands role policy includes (W41-10).
func (r *RBAC) ResolvePolicyNames(names []string) []string {
	seen := make(map[string]struct{})
	var out []string
	var walk func([]string)
	walk = func(batch []string) {
		for _, name := range batch {
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			policy, ok := r.policy(name)
			if !ok {
				out = append(out, name)
				continue
			}
			if len(policy.Includes) > 0 {
				walk(policy.Includes)
			}
			out = append(out, name)
		}
	}
	walk(names)
	return out
}
