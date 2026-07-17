// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"time"
)

// LeaseTuning holds role-level lease configuration (W42-04).
type LeaseTuning struct {
	DefaultTTL int
	MaxTTL     int
	Period     int
	Renewable  bool
	MaxLeases  int
}

// LeaseTuningFromDatabaseRole extracts lease tuning from a database role.
func LeaseTuningFromDatabaseRole(r *DatabaseRole) LeaseTuning {
	if r == nil {
		return LeaseTuning{}
	}
	t := LeaseTuning{
		DefaultTTL: r.DefaultTTL,
		MaxTTL:     r.MaxTTL,
		Period:     r.Period,
		Renewable:  r.Renewable,
		MaxLeases:  r.MaxLeases,
	}
	if t.DefaultTTL <= 0 {
		t.DefaultTTL = r.TTLSeconds
	}
	if t.MaxTTL <= 0 {
		t.MaxTTL = t.DefaultTTL
	}
	if t.DefaultTTL <= 0 {
		t.DefaultTTL = 3600
	}
	if t.MaxTTL <= 0 {
		t.MaxTTL = t.DefaultTTL
	}
	return t
}

// LeaseTuningFromSSHRole extracts lease tuning from an SSH role.
func LeaseTuningFromSSHRole(r *SSHRole) LeaseTuning {
	if r == nil {
		return LeaseTuning{}
	}
	t := LeaseTuning{
		DefaultTTL: r.DefaultTTL,
		MaxTTL:     r.MaxTTL,
		Period:     r.Period,
		Renewable:  r.Renewable,
		MaxLeases:  r.MaxLeases,
	}
	if t.DefaultTTL <= 0 {
		t.DefaultTTL = r.TTLSeconds
	}
	if t.MaxTTL <= 0 {
		t.MaxTTL = t.DefaultTTL
	}
	if t.DefaultTTL <= 0 {
		t.DefaultTTL = 3600
	}
	if t.MaxTTL <= 0 {
		t.MaxTTL = t.DefaultTTL
	}
	return t
}

// ResolveIssueTTL picks TTL for credential issuance.
func (t LeaseTuning) ResolveIssueTTL(requested int) (int, error) {
	ttl := t.DefaultTTL
	if requested > 0 {
		ttl = requested
	}
	if t.Period > 0 {
		ttl = t.Period
	}
	if ttl <= 0 {
		return 0, fmt.Errorf("ttl must be positive")
	}
	if ttl > t.MaxTTL {
		return 0, fmt.Errorf("requested ttl %ds exceeds role max_ttl %ds", ttl, t.MaxTTL)
	}
	return ttl, nil
}

// ResolveRenewTTL caps renewal increment to role max_ttl from now (W42-05).
func (t LeaseTuning) ResolveRenewTTL(requested, currentTTL int, now, expiresAt time.Time) int {
	if requested <= 0 {
		requested = currentTTL
	}
	if t.Period > 0 {
		requested = t.Period
	}
	maxUntil := now.Add(time.Duration(t.MaxTTL) * time.Second)
	candidate := now.Add(time.Duration(requested) * time.Second)
	if candidate.After(maxUntil) {
		return int(maxUntil.Sub(now).Seconds())
	}
	return requested
}

// LeaseWarnings emits warnings when expiry is within grace window.
func LeaseWarnings(now, expiresAt time.Time, ttlSeconds int) []string {
	if ttlSeconds <= 0 {
		return nil
	}
	remaining := expiresAt.Sub(now)
	total := time.Duration(ttlSeconds) * time.Second
	if remaining <= 0 {
		return []string{"lease has expired"}
	}
	if remaining < total/10 {
		return []string{fmt.Sprintf("lease expires in %s (less than 10%% of ttl remaining)", remaining.Round(time.Second))}
	}
	return nil
}

// NormalizeDatabaseLeaseTuning applies defaults on database roles.
func NormalizeDatabaseLeaseTuning(role *DatabaseRole) {
	if role == nil {
		return
	}
	if role.DefaultTTL <= 0 {
		role.DefaultTTL = role.TTLSeconds
	}
	if role.MaxTTL <= 0 {
		role.MaxTTL = role.DefaultTTL
	}
	if role.TTLSeconds <= 0 {
		role.TTLSeconds = role.DefaultTTL
	}
}
