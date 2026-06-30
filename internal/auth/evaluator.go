package auth

import (
	"net"
	"strings"
	"time"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

// RequestContext carries request metadata for policy condition evaluation.
type RequestContext struct {
	ClientIP  string
	Namespace string
	Resource  string
	Action    string
	Now       time.Time
}

// ConditionsMatch returns true when all policy conditions pass for the request.
func ConditionsMatch(conditions map[string]any, req RequestContext) bool {
	if len(conditions) == 0 {
		return true
	}
	if req.Now.IsZero() {
		req.Now = time.Now().UTC()
	}

	if cidrs, ok := conditions["ip_cidr"].([]any); ok && len(cidrs) > 0 {
		if !matchIPCIDR(cidrs, req.ClientIP) {
			return false
		}
	}
	if after, ok := conditions["time_after"].(string); ok && after != "" {
		t, err := time.Parse(time.RFC3339, after)
		if err != nil || req.Now.Before(t) {
			return false
		}
	}
	if before, ok := conditions["time_before"].(string); ok && before != "" {
		t, err := time.Parse(time.RFC3339, before)
		if err != nil || !req.Now.Before(t) {
			return false
		}
	}
	if prefix, ok := conditions["path_prefix"].(string); ok && prefix != "" {
		if !strings.HasPrefix(req.Resource, prefix) {
			return false
		}
	}
	if ns, ok := conditions["namespace"].(string); ok && ns != "" {
		if req.Namespace != ns {
			return false
		}
	}
	return true
}

func matchIPCIDR(cidrs []any, clientIP string) bool {
	if clientIP == "" {
		return false
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, raw := range cidrs {
		pattern, ok := raw.(string)
		if !ok || pattern == "" {
			continue
		}
		_, network, err := net.ParseCIDR(pattern)
		if err != nil {
			if pattern == clientIP {
				return true
			}
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// PolicyMatches evaluates resource/action and conditions for a policy.
func PolicyMatches(policy domainauth.Policy, resource, action string, req RequestContext) bool {
	if !policyMatchesResourceAction(policy, resource, action) {
		return false
	}
	req.Resource = resource
	req.Action = action
	return ConditionsMatch(policy.Conditions, req)
}

func policyMatchesResourceAction(policy domainauth.Policy, resource, action string) bool {
	for _, resPattern := range policy.Resources {
		if !domainauth.MatchResource(resPattern, resource) {
			continue
		}
		for _, actPattern := range policy.Actions {
			if domainauth.MatchAction(actPattern, action) {
				return true
			}
		}
	}
	return false
}
