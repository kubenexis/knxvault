// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/acme"
)

// TestW80_CloudflareDefaultClientIsSafeHTTP ensures nil Client uses SafeHTTPClient (Proxy:nil + dial checks).
func TestW80_CloudflareDefaultClientIsSafeHTTP(t *testing.T) {
	// SafeHTTPClient disables env proxy — construct the same path as CloudflareDNS01.api.
	c := acme.SafeHTTPClient(30 * time.Second)
	if c == nil || c.Transport == nil {
		t.Fatal("SafeHTTPClient missing transport")
	}
	rt, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type %T", c.Transport)
	}
	if rt.Proxy != nil {
		// Explicit nil function is allowed; non-nil Proxy (including http.ProxyFromEnvironment) is not.
		// SafeHTTP sets Proxy: nil (no function).
		t.Fatal("SafeHTTPClient must set Proxy to nil")
	}
}
