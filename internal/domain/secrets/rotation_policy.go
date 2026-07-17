// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"time"
)

// Rotation generators.
const (
	GeneratorRandomPassword = "random_password"
	GeneratorScriptRef      = "script_ref"
)

// RotationPolicy schedules automatic KV value rotation.
type RotationPolicy struct {
	Path          string    `json:"path"`
	Interval      int64     `json:"interval_seconds"`
	Generator     string    `json:"generator"`
	ScriptRef     string    `json:"script_ref,omitempty"`
	LastRotatedAt time.Time `json:"last_rotated_at,omitempty"`
	Enabled       bool      `json:"enabled"`
}

// Validate checks rotation policy fields.
func (p *RotationPolicy) Validate() error {
	if p.Path == "" {
		return fmt.Errorf("rotation path is required")
	}
	if p.Interval <= 0 {
		return fmt.Errorf("rotation interval must be positive")
	}
	switch p.Generator {
	case GeneratorRandomPassword, GeneratorScriptRef:
	default:
		return fmt.Errorf("invalid rotation generator %q", p.Generator)
	}
	if p.Generator == GeneratorScriptRef && p.ScriptRef == "" {
		return fmt.Errorf("script_ref required for script_ref generator")
	}
	return nil
}

// Due reports whether the policy should run at now.
func (p *RotationPolicy) Due(now time.Time) bool {
	if !p.Enabled {
		return false
	}
	if p.LastRotatedAt.IsZero() {
		return true
	}
	return now.Sub(p.LastRotatedAt) >= time.Duration(p.Interval)*time.Second
}
