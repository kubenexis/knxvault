// Package renew computes certificate renewal timing for the operator.
package renew

import (
	"time"
)

// Defaults when CR fields are empty.
const (
	DefaultDuration    = 90 * 24 * time.Hour // 2160h
	DefaultRenewBefore = 30 * 24 * time.Hour // 720h
)

// ParseDuration accepts Go duration or empty (returns def).
func ParseDuration(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	return time.ParseDuration(s)
}

// NeedsRenew reports whether a cert with notAfter should be re-issued given renewBefore.
// notAfter may be RFC3339 or empty (treat as needs issue).
func NeedsRenew(notAfter string, renewBefore time.Duration, now time.Time) bool {
	if notAfter == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		// Try common alternate from vault (RFC3339Nano / without Z).
		t, err = time.Parse(time.RFC3339Nano, notAfter)
		if err != nil {
			return true
		}
	}
	return !now.Before(t.Add(-renewBefore))
}

// RequeueAfter returns how long to wait before next renew check.
// Zero or negative means requeue ASAP.
func RequeueAfter(notAfter string, renewBefore time.Duration, now time.Time) time.Duration {
	if notAfter == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, notAfter)
		if err != nil {
			return time.Minute
		}
	}
	deadline := t.Add(-renewBefore)
	d := deadline.Sub(now)
	if d < 0 {
		return 0
	}
	// Cap minimum requeue so we don't spin; maximum 24h for safety.
	if d > 24*time.Hour {
		return 24 * time.Hour
	}
	return d
}

// IsClientUsage returns true if usages request a client certificate.
func IsClientUsage(usages []string) bool {
	for _, u := range usages {
		switch u {
		case "client auth", "client", "ClientAuth", "clientAuth":
			return true
		}
	}
	return false
}
