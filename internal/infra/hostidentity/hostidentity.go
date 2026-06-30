// Package hostidentity resolves pod hostname and StatefulSet ordinal node IDs.
package hostidentity

import (
	"os"
	"strconv"
	"strings"
)

// Hostname returns the pod or host identity used for Raft and HA leader election.
func Hostname() string {
	if v := strings.TrimSpace(os.Getenv("KNXVAULT_POD_NAME")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("HOSTNAME")); v != "" {
		return v
	}
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return host
}

// NodeIDFromHostname derives a 1-based Raft node ID from a StatefulSet pod suffix.
func NodeIDFromHostname(host string) uint64 {
	parts := strings.Split(host, "-")
	if len(parts) < 2 {
		return 0
	}
	ord, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	if err != nil {
		return 0
	}
	return ord + 1
}
