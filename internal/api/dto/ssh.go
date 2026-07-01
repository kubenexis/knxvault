package dto

import "time"

// SSHRoleRequest configures an OpenSSH credential role.
type SSHRoleRequest struct {
	TTLSeconds   int               `json:"ttl_seconds"`
	CAKeyPath    string            `json:"ca_key_path"`
	AllowedUsers []string          `json:"allowed_users,omitempty"`
	DefaultUser  string            `json:"default_user,omitempty"`
	KeyType      string            `json:"key_type,omitempty"`
	Extensions   map[string]string `json:"extensions,omitempty"`
}

// SSHRoleResponse returns SSH role configuration.
type SSHRoleResponse struct {
	Name         string            `json:"name"`
	TTLSeconds   int               `json:"ttl_seconds"`
	CAKeyPath    string            `json:"ca_key_path"`
	AllowedUsers []string          `json:"allowed_users,omitempty"`
	DefaultUser  string            `json:"default_user,omitempty"`
	KeyType      string            `json:"key_type,omitempty"`
	Extensions   map[string]string `json:"extensions,omitempty"`
}

// SSHCredsRequest optionally overrides username or TTL for credential generation.
type SSHCredsRequest struct {
	Username   string `json:"username,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

// SSHCredsResponse is returned for SSH credential generation.
type SSHCredsResponse struct {
	LeaseID    string    `json:"lease_id"`
	Username   string    `json:"username"`
	PrivateKey string    `json:"private_key"`
	SignedKey  string    `json:"signed_key"`
	Role       string    `json:"role"`
	TTLSeconds int       `json:"ttl_seconds"`
	ExpiresAt  time.Time `json:"expires_at"`
}