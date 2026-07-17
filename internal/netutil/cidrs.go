package netutil

import (
	"fmt"
	"net"
	"strings"
)

// ParseCIDRs parses comma-separated or slice CIDRs/IPs into *net.IPNet list.
func ParseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			// Single IP → /32 or /128
			ip := net.ParseIP(raw)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP %q", raw)
			}
			if ip.To4() != nil {
				raw += "/32"
			} else {
				raw += "/128"
			}
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// IPAllowed reports whether ip is inside any network. Empty nets = allow all.
func IPAllowed(ipStr string, nets []*net.IPNet) bool {
	if len(nets) == 0 {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
