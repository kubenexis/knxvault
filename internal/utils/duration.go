// Package utils provides shared helpers.
package utils

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MaxParseTTL caps parsed durations (≈10y) to avoid overflow / absurd cert or token lifetimes.
const MaxParseTTL = 10 * 365 * 24 * time.Hour

// ParseTTL parses duration strings like "8760h", "365d", "30m".
// Rejects non-positive and over-MaxParseTTL values.
func ParseTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("ttl is required")
	}

	var d time.Duration
	if parsed, err := time.ParseDuration(raw); err == nil {
		d = parsed
	} else {
		if len(raw) < 2 {
			return 0, fmt.Errorf("invalid ttl %q", raw)
		}
		unit := raw[len(raw)-1]
		value, err := strconv.Atoi(raw[:len(raw)-1])
		if err != nil {
			return 0, fmt.Errorf("invalid ttl %q", raw)
		}
		if value <= 0 {
			return 0, fmt.Errorf("ttl must be positive")
		}
		switch unit {
		case 'd':
			d = time.Duration(value) * 24 * time.Hour
		case 'h':
			d = time.Duration(value) * time.Hour
		case 'm':
			d = time.Duration(value) * time.Minute
		case 's':
			d = time.Duration(value) * time.Second
		default:
			return 0, fmt.Errorf("unsupported ttl unit in %q", raw)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("ttl must be positive")
	}
	if d > MaxParseTTL {
		return 0, fmt.Errorf("ttl exceeds maximum of %s", MaxParseTTL)
	}
	return d, nil
}
