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

// Auth method types for role login.
const (
	AuthMethodKubernetes = "kubernetes"
	AuthMethodOIDC       = "oidc"
)

// ClaimMapping maps an OIDC claim value to policies.
type ClaimMapping struct {
	Claim    string   `json:"claim"`
	Match    string   `json:"match"`
	Regex    bool     `json:"regex,omitempty"`
	Policies []string `json:"policies"`
}

// OIDCConfig configures OIDC/JWT login for a role.
type OIDCConfig struct {
	Issuer        string            `json:"issuer"`
	Audience      string            `json:"audience"`
	JWKSURL       string            `json:"jwks_url"`
	MaxTTL        int64             `json:"max_ttl_seconds"`
	ClaimMappings []ClaimMapping    `json:"claim_mappings,omitempty"`
	BoundClaims   map[string]string `json:"bound_claims,omitempty"`
}

// Role binds policy names to a role identifier and optional Kubernetes ServiceAccount constraints.
type Role struct {
	Name                          string
	Policies                      []string
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
	AuthMethod                    string
	OIDC                          *OIDCConfig
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
