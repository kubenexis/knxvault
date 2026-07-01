package config

import (
	"fmt"
	"strings"
)

const (
	UnsealSchemeSingle     = "single"
	UnsealSchemeShamir     = "shamir"
	AutoUnsealProviderFile = "file"
)

// SealConfig holds operational seal/unseal settings.
type SealConfig struct {
	Scheme             string
	Threshold          int
	Shares             int
	AutoUnsealProvider string
	AutoUnsealKeyFile  string
	BreakGlassShamir   bool
}

// Validate checks seal configuration consistency.
func (s SealConfig) Validate() error {
	scheme := strings.ToLower(strings.TrimSpace(s.Scheme))
	if scheme == "" {
		scheme = UnsealSchemeSingle
	}
	switch scheme {
	case UnsealSchemeSingle:
		return nil
	case UnsealSchemeShamir:
		if s.Threshold < 2 {
			return fmt.Errorf("KNXVAULT_UNSEAL_THRESHOLD must be >= 2 for shamir")
		}
		if s.Shares < s.Threshold {
			return fmt.Errorf("KNXVAULT_UNSEAL_SHARES must be >= threshold")
		}
		return nil
	default:
		return fmt.Errorf("unknown KNXVAULT_UNSEAL_SCHEME %q", s.Scheme)
	}
}

// ShamirEnabled reports whether Shamir threshold unseal is configured.
func (s SealConfig) ShamirEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(s.Scheme), UnsealSchemeShamir)
}

// AutoUnsealEnabled reports whether startup auto-unseal is configured.
func (s SealConfig) AutoUnsealEnabled() bool {
	return strings.TrimSpace(s.AutoUnsealProvider) != ""
}
