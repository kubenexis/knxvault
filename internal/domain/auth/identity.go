package auth

import (
	"fmt"
	"time"
)

// Entity is a first-class identity (person or machine) that aliases map onto.
type Entity struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Disabled bool              `json:"disabled,omitempty"`
	Policies []string          `json:"policies,omitempty"`
	Created  time.Time         `json:"created_at"`
	Updated  time.Time         `json:"updated_at"`
}

// Validate checks required entity fields.
func (e *Entity) Validate() error {
	if e == nil {
		return fmt.Errorf("entity is nil")
	}
	if e.ID == "" {
		return fmt.Errorf("entity id is required")
	}
	if e.Name == "" {
		return fmt.Errorf("entity name is required")
	}
	return nil
}

// Alias links an auth method principal to an entity.
type Alias struct {
	ID       string    `json:"id"`
	EntityID string    `json:"entity_id"`
	Mount    string    `json:"mount"` // e.g. kubernetes, oidc, approle, ldap, jwt
	Name     string    `json:"name"`  // unique within mount
	Created  time.Time `json:"created_at"`
}

// Validate checks required alias fields.
func (a *Alias) Validate() error {
	if a == nil {
		return fmt.Errorf("alias is nil")
	}
	if a.ID == "" {
		return fmt.Errorf("alias id is required")
	}
	if a.EntityID == "" {
		return fmt.Errorf("entity_id is required")
	}
	if a.Mount == "" {
		return fmt.Errorf("mount is required")
	}
	if a.Name == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}

// Group aggregates entities and attaches policies.
type Group struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	MemberIDs []string  `json:"member_entity_ids,omitempty"`
	Policies  []string  `json:"policies,omitempty"`
	Created   time.Time `json:"created_at"`
	Updated   time.Time `json:"updated_at"`
}

// Validate checks required group fields.
func (g *Group) Validate() error {
	if g == nil {
		return fmt.Errorf("group is nil")
	}
	if g.ID == "" {
		return fmt.Errorf("group id is required")
	}
	if g.Name == "" {
		return fmt.Errorf("group name is required")
	}
	return nil
}
