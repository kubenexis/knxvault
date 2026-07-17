// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package netutil holds shared network validation helpers.
package netutil

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateVaultBaseURL rejects cleartext non-loopback vault addresses (W52-06).
// When requireHTTPS is false, any http/https URL is accepted.
// Loopback http://127.0.0.1 and http://localhost remain allowed for lab even when requireHTTPS.
func ValidateVaultBaseURL(raw string, requireHTTPS bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("vault address is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid vault address: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("vault address scheme must be http or https")
	}
	if !requireHTTPS || scheme == "https" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return nil
	}
	return fmt.Errorf("vault address must use https (loopback http allowed for lab only)")
}
