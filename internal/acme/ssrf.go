package acme

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateOutboundURL rejects SSRF-prone destinations for webhooks (W50-07).
// Allows http/https only; blocks loopback, link-local, private RFC1918, metadata IPs.
// Resolves hostnames and fail-closes on DNS failure (webhook posts).
func ValidateOutboundURL(raw string) error {
	return validateOutboundURL(raw, true)
}

// ValidateDirectoryURL applies static SSRF checks for ACME directory URLs without
// requiring DNS resolution (admin-configured directories may be mock/lab hostnames).
// Still blocks private IP literals and metadata hostnames.
func ValidateDirectoryURL(raw string) error {
	return validateOutboundURL(raw, false)
}

func validateOutboundURL(raw string, resolveDNS bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("url scheme must be http or https")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("url host required")
	}
	// Block obvious metadata hostnames.
	lh := strings.ToLower(host)
	if lh == "metadata.google.internal" || lh == "metadata" || strings.HasSuffix(lh, ".internal") {
		return fmt.Errorf("url host not allowed")
	}
	// If host is an IP literal, check private ranges.
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("url host is not a public address")
		}
		return nil
	}
	if !resolveDNS {
		return nil
	}
	// Hostname: resolve and check all answers (webhooks).
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("url host resolve failed: %w", err)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("url host resolves to a non-public address")
		}
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// Cloud metadata 169.254.169.254 is link-local already.
	return false
}

// PublicLEHost reports whether host is a known public Let's Encrypt directory host.
// Uses suffix match so hostnames like "evil-letsencrypt.org.example" are not treated as LE.
func PublicLEHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "letsencrypt.org" || strings.HasSuffix(h, ".letsencrypt.org")
}
