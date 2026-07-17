// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme_test

import (
	"net/http"
	"testing"

	"github.com/kubenexis/knxvault/internal/acme"
)

func TestW79_BlocksCGNATAndDocsRanges(t *testing.T) {
	for _, raw := range []string{
		"http://100.64.0.1/",
		"http://100.127.1.1/",
		"http://198.18.0.1/",
		"http://203.0.113.10/",
		"http://metadata.google.internal/",
	} {
		if err := acme.ValidateDirectoryURL(raw); err == nil {
			t.Fatalf("expected block for %s", raw)
		}
	}
	if err := acme.ValidateDirectoryURL("https://acme-v02.api.letsencrypt.org/directory"); err != nil {
		t.Fatal(err)
	}
}

func TestW79_SafeHTTPClientDisablesEnvProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("http_proxy", "http://127.0.0.1:9")
	t.Setenv("https_proxy", "http://127.0.0.1:9")
	client := acme.SafeHTTPClient(5)
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr == nil {
		t.Fatal("expected *http.Transport")
	}
	if tr.Proxy != nil {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		u, err := tr.Proxy(req)
		if err != nil {
			t.Fatal(err)
		}
		if u != nil {
			t.Fatalf("expected no proxy, got %v", u)
		}
	}
}

func TestW79_ProfileValidateSSRFWithSkipTLS(t *testing.T) {
	p := &acme.Profile{
		AcceptTOS:     true,
		Email:         "a@b.com",
		DirectoryURL:  "http://10.0.0.1/dir",
		SkipTLSVerify: true,
		Domains:       []acme.ProfileDomain{{Name: "x.example.com"}},
		HTTP01:        &acme.ProfileHTTP01{Mode: "webroot", Webroot: t.TempDir()},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected private directory rejected even with skipTLS")
	}
}
