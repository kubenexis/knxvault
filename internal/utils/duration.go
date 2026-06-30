// Package utils provides shared helpers.
package utils

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseTTL parses duration strings like "8760h", "365d", "30m".
func ParseTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("ttl is required")
	}

	if d, err := time.ParseDuration(raw); err == nil {
		return d, nil
	}

	if len(raw) < 2 {
		return 0, fmt.Errorf("invalid ttl %q", raw)
	}

	unit := raw[len(raw)-1]
	value, err := strconv.Atoi(raw[:len(raw)-1])
	if err != nil {
		return 0, fmt.Errorf("invalid ttl %q", raw)
	}

	switch unit {
	case 'd':
		return time.Duration(value) * 24 * time.Hour, nil
	case 'h':
		return time.Duration(value) * time.Hour, nil
	case 'm':
		return time.Duration(value) * time.Minute, nil
	case 's':
		return time.Duration(value) * time.Second, nil
	default:
		return 0, fmt.Errorf("unsupported ttl unit in %q", raw)
	}
}
