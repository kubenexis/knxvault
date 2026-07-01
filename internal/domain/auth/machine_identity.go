package auth

import (
	"fmt"
	"time"
)

// Machine identity types.
const (
	IdentityTypeK8sSA  = "k8s_sa"
	IdentityTypeOIDC   = "oidc"
	IdentityTypeAPIKey = "api_key"
	IdentityTypeAgent  = "agent"
)

// MachineIdentity is a first-class non-human identity (NHI).
type MachineIdentity struct {
	ID               string    `json:"id"`
	Type             string    `json:"type"`
	BoundNamespace   string    `json:"bound_namespace,omitempty"`
	BoundName        string    `json:"bound_name,omitempty"`
	Policies         []string  `json:"policies"`
	MaxTTL           int64     `json:"max_ttl_seconds,omitempty"`
	LastSeen         time.Time `json:"last_seen"`
	Revoked          bool      `json:"revoked"`
	ParentIdentityID string    `json:"parent_identity_id,omitempty"`
}

// Validate checks machine identity fields.
func (m *MachineIdentity) Validate() error {
	if m.ID == "" {
		return fmt.Errorf("machine identity id is required")
	}
	if m.Type == "" {
		return fmt.Errorf("machine identity type is required")
	}
	switch m.Type {
	case IdentityTypeK8sSA, IdentityTypeOIDC, IdentityTypeAPIKey, IdentityTypeAgent:
	default:
		return fmt.Errorf("invalid machine identity type %q", m.Type)
	}
	return nil
}

// NHIKey builds a stable identity key from type and bindings.
func NHIKey(typ, namespace, name, subject string) string {
	switch typ {
	case IdentityTypeK8sSA:
		return fmt.Sprintf("k8s_sa:%s:%s", namespace, name)
	case IdentityTypeOIDC:
		return fmt.Sprintf("oidc:%s", subject)
	default:
		return fmt.Sprintf("%s:%s", typ, subject)
	}
}
