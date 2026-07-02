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
	ID           uuid.UUID
	Name         string
	Effect       Effect
	Resources    []string
	Actions      []string
	Capabilities []string
	Includes     []string
	Conditions   map[string]any
}

// Validate checks policy fields.
func (p *Policy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if p.Effect != EffectAllow && p.Effect != EffectDeny {
		return fmt.Errorf("invalid policy effect %q", p.Effect)
	}
	if len(p.Resources) == 0 {
		return fmt.Errorf("policy resources are required")
	}
	if len(p.Capabilities) == 0 && len(p.Actions) == 0 {
		return fmt.Errorf("policy capabilities or actions are required")
	}
	for _, r := range p.Resources {
		if strings.ContainsAny(r, "*?") && strings.Count(r, "**") > 1 {
			return fmt.Errorf("ambiguous glob pattern %q", r)
		}
	}
	return nil
}

// Auth method types for role login.
const (
	AuthMethodKubernetes = "kubernetes"
	AuthMethodOIDC       = "oidc"
)

// OIDCConfig configures OIDC/JWT login for a role.
type OIDCConfig struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	JWKSURL  string `json:"jwks_url"`
	MaxTTL   int64  `json:"max_ttl_seconds"`
}

// Role binds policy names to a role identifier and optional Kubernetes ServiceAccount constraints.
type Role struct {
	Name                          string
	Policies                      []string
	PolicyGroups                  []string
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
	AuthMethod                    string
	OIDC                          *OIDCConfig
	RequireMFA                    bool
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

// MatchResource returns true when resource matches a pattern like "pki/*" or glob "team-?/app-*".
func MatchResource(pattern, resource string) bool {
	if pattern == "*" || pattern == "*/*" {
		return true
	}
	// Single trailing /* is prefix semantics (legacy), not full glob.
	if strings.HasSuffix(pattern, "/*") && !strings.Contains(strings.TrimSuffix(pattern, "/*"), "*") && !strings.Contains(pattern, "?") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return resource == prefix || strings.HasPrefix(resource, prefix+"/")
	}
	if strings.ContainsAny(pattern, "*?") {
		return matchResourceGlob(pattern, resource)
	}
	return pattern == resource
}

func matchResourceGlob(pattern, resource string) bool {
	// Inline glob to avoid import cycle with internal/auth.
	if pattern == "*" || pattern == "*/*" {
		return true
	}
	return globMatch(pattern, resource, 0, 0)
}

func globMatch(pat, str string, pi, si int) bool {
	for pi < len(pat) {
		switch pat[pi] {
		case '*':
			if pi+1 < len(pat) && pat[pi+1] == '*' {
				if pi+2 < len(pat) && pat[pi+2] == '/' {
					pi += 3
					for si <= len(str) {
						if globMatch(pat, str, pi, si) {
							return true
						}
						if si == len(str) {
							break
						}
						next := strings.IndexByte(str[si:], '/')
						if next < 0 {
							si = len(str)
						} else {
							si += next + 1
						}
					}
					return false
				}
				pi += 2
				for si <= len(str) {
					if globMatch(pat, str, pi, si) {
						return true
					}
					si++
				}
				return false
			}
			pi++
			for si <= len(str) {
				if globMatch(pat, str, pi, si) {
					return true
				}
				si++
			}
			return false
		case '?':
			if si >= len(str) || str[si] == '/' {
				return false
			}
			pi++
			si++
		default:
			if si >= len(str) || pat[pi] != str[si] {
				return false
			}
			pi++
			si++
		}
	}
	return si == len(str)
}

// MatchAction returns true when action matches pattern or "*".
func MatchAction(pattern, action string) bool {
	return pattern == "*" || pattern == action
}
