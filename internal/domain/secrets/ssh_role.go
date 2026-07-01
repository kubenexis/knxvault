package secrets

import (
	"fmt"
	"strings"
	"time"
)

const (
	SSHKeyTypeED25519 = "ed25519"
	SSHKeyTypeRSA     = "rsa"
)

// SSHRole configures dynamic OpenSSH user certificate issuance.
type SSHRole struct {
	Name         string
	TTLSeconds   int
	CAKeyPath    string
	AllowedUsers []string
	DefaultUser  string
	KeyType      string
	Extensions   map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// NormalizeSSHRole applies defaults to role configuration.
func NormalizeSSHRole(r *SSHRole) {
	if r == nil {
		return
	}
	if r.TTLSeconds <= 0 {
		r.TTLSeconds = 3600
	}
	if r.KeyType == "" {
		r.KeyType = SSHKeyTypeED25519
	}
	if r.Extensions == nil {
		r.Extensions = map[string]string{
			"permit-pty":             "",
			"permit-port-forwarding": "",
		}
	}
}

// Validate checks SSH role configuration.
func (r *SSHRole) Validate() error {
	NormalizeSSHRole(r)
	if r.Name == "" {
		return fmt.Errorf("ssh role name is required")
	}
	if r.TTLSeconds <= 0 {
		return fmt.Errorf("ssh role ttl must be positive")
	}
	if strings.TrimSpace(r.CAKeyPath) == "" {
		return fmt.Errorf("ca_key_path is required")
	}
	switch r.KeyType {
	case SSHKeyTypeED25519, SSHKeyTypeRSA:
	default:
		return fmt.Errorf("invalid ssh key_type %q", r.KeyType)
	}
	if r.DefaultUser == "" && len(r.AllowedUsers) == 0 {
		return fmt.Errorf("default_user or allowed_users is required")
	}
	return nil
}

// AllowedUser reports whether username is permitted by role policy.
func (r *SSHRole) AllowedUser(username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}
	if len(r.AllowedUsers) == 0 {
		return r.DefaultUser == "" || r.DefaultUser == username
	}
	for _, allowed := range r.AllowedUsers {
		if strings.TrimSpace(allowed) == username {
			return true
		}
	}
	return false
}
