// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
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
	// Block obvious metadata / internal hostnames (W79).
	lh := strings.ToLower(host)
	if isBlockedHostname(lh) {
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

func isBlockedHostname(host string) bool {
	switch host {
	case "metadata", "metadata.google.internal", "metadata.goog",
		"kubernetes.default", "kubernetes.default.svc",
		"instance-data", "instance-data.ec2.internal":
		return true
	}
	if strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".localhost") {
		return true
	}
	// AWS IMDS hostname variants
	if strings.Contains(host, "169.254.169.254") {
		return true
	}
	return false
}

// isBlockedIP reports non-public destinations (W79 expands CGNAT + docs ranges).
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// CGNAT / shared address space (RFC 6598) — not IsPrivate in Go.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		// Benchmark / documentation (RFC 5737, 2544)
		if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
			return true
		}
		if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
			return true
		}
		if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
			return true
		}
	}
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

// IsLoopbackDirectoryURL reports whether the directory host is loopback (lab ACME / Pebble).
func IsLoopbackDirectoryURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// SafeHTTPClient returns an HTTP client that re-validates resolved IPs at dial time
// (mitigates DNS rebinding for webhooks; W74 ACME SSRF).
func SafeHTTPClient(timeout time.Duration) *http.Client {
	return safeHTTPClient(timeout, false, false)
}

// SafeHTTPClientAllowLoopback allows 127.0.0.1/::1 for local agents (audit SIEM, lab)
// but still blocks RFC1918 and link-local/metadata.
func SafeHTTPClientAllowLoopback(timeout time.Duration) *http.Client {
	return safeHTTPClient(timeout, true, false)
}

// SafeHTTPClientAllowLoopbackInsecureTLS is for lab ACME (Pebble) only: allows loopback
// dial targets and skips TLS verification. Still blocks RFC1918/metadata/non-loopback private.
func SafeHTTPClientAllowLoopbackInsecureTLS(timeout time.Duration) *http.Client {
	return safeHTTPClient(timeout, true, true)
}

func safeHTTPClient(timeout time.Duration, allowLoopback, insecureTLS bool) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		// W79-01: never honor HTTP(S)_PROXY — dial-time SSRF checks would only see the proxy.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("resolve %s: %w", host, err)
			}
			var last error
			for _, ipa := range ips {
				if allowLoopback && ipa.IP.IsLoopback() {
					// allowed for lab
				} else if isBlockedIP(ipa.IP) {
					last = fmt.Errorf("blocked address %s", ipa.IP)
					continue
				}
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			if last == nil {
				last = fmt.Errorf("no allowed addresses for %s", host)
			}
			return nil, last
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // #nosec G402 — lab loopback only
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("redirects not allowed")
		},
	}
}
