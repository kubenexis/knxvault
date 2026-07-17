// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net"
	"strings"
	"time"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

// RequestContext carries request metadata for policy condition evaluation.
type RequestContext struct {
	ClientIP       string
	Namespace      string
	Resource       string
	Action         string
	AgentID        string
	Now            time.Time
	Cluster        string
	Environment    string
	RequestPath    string
	RequestID      string
	ResourceLabels map[string]string
}

// ConditionsMatch returns true when all policy conditions pass for the request.
func ConditionsMatch(conditions map[string]any, req RequestContext) bool {
	if len(conditions) == 0 {
		return true
	}
	if req.Now.IsZero() {
		req.Now = time.Now().UTC()
	}

	if raw, ok := conditions["ip_cidr"]; ok && raw != nil {
		if !matchIPCIDRAny(raw, req.ClientIP) {
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
	if agentID, ok := conditions["agent_id"].(string); ok && agentID != "" {
		if req.AgentID != agentID {
			return false
		}
	}
	if cluster, ok := conditions["cluster"].(string); ok && cluster != "" {
		if req.Cluster != cluster {
			return false
		}
	}
	if env, ok := conditions["environment"].(string); ok && env != "" {
		if req.Environment != env {
			return false
		}
	}
	if reqPath, ok := conditions["request_path"].(string); ok && reqPath != "" {
		if req.RequestPath != reqPath && !strings.HasPrefix(req.RequestPath, reqPath) {
			return false
		}
	}
	if labelKey, ok := conditions["resource_label"].(string); ok && labelKey != "" {
		expected, ok := conditions["resource_label_value"].(string)
		if !ok || expected == "" {
			return false
		}
		if req.ResourceLabels == nil || req.ResourceLabels[labelKey] != expected {
			return false
		}
	}
	if owner, ok := conditions["owner_match"].(string); ok && owner != "" {
		if req.ResourceLabels == nil || req.ResourceLabels["owner"] != owner {
			return false
		}
	}
	return true
}

func matchIPCIDRAny(raw any, clientIP string) bool {
	switch v := raw.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return false
		}
		return matchIPCIDR([]any{v}, clientIP)
	case []any:
		return len(v) > 0 && matchIPCIDR(v, clientIP)
	case []string:
		if len(v) == 0 {
			return false
		}
		anyList := make([]any, len(v))
		for i, s := range v {
			anyList[i] = s
		}
		return matchIPCIDR(anyList, clientIP)
	default:
		return false
	}
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
	actions := policy.Actions
	if len(policy.Capabilities) > 0 {
		actions = policy.Capabilities
	}
	for _, resPattern := range policy.Resources {
		if !domainauth.MatchResource(resPattern, resource) {
			continue
		}
		for _, actPattern := range actions {
			if domainauth.MatchAction(actPattern, action) {
				return true
			}
		}
	}
	return false
}
