package auth

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Effect is allow or deny.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Policy describes RBAC permissions (LLD §4.C.2).
type Policy struct {
	ID         uuid.UUID
	Name       string
	Effect     Effect
	Resources  []string
	Actions    []string
	Conditions map[string]any
}

// Validate checks policy fields.
func (p *Policy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if p.Effect != EffectAllow && p.Effect != EffectDeny {
		return fmt.Errorf("invalid policy effect %q", p.Effect)
	}
	if len(p.Resources) == 0 || len(p.Actions) == 0 {
		return fmt.Errorf("policy resources and actions are required")
	}
	return nil
}

// Role binds policy names to a role identifier and optional Kubernetes ServiceAccount constraints.
type Role struct {
	Name                          string
	Policies                      []string
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
}

// Validate checks role fields.
func (r *Role) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("role name is required")
	}
	if len(r.Policies) == 0 {
		return fmt.Errorf("role requires at least one policy")
	}
	return nil
}

// MatchResource returns true when resource matches a pattern like "pki/*".
func MatchResource(pattern, resource string) bool {
	if pattern == "*" || pattern == "*/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return resource == prefix || strings.HasPrefix(resource, prefix+"/")
	}
	return pattern == resource
}

// MatchAction returns true when action matches pattern or "*".
func MatchAction(pattern, action string) bool {
	return pattern == "*" || pattern == action
}
