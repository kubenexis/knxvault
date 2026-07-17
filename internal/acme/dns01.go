// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// DNS01FQDN returns the FQDN for the ACME DNS-01 TXT record.
func DNS01FQDN(domain string) string {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	return "_acme-challenge." + domain + "."
}

// MemoryDNS01 records DNS-01 presentations for tests / manual inspection.
type MemoryDNS01 struct {
	// Records maps FQDN → TXT values (multi-value).
	Records map[string][]string
}

// NewMemoryDNS01 constructs an empty DNS-01 store.
func NewMemoryDNS01() *MemoryDNS01 {
	return &MemoryDNS01{Records: make(map[string][]string)}
}

// Present appends a TXT value for the challenge FQDN.
func (m *MemoryDNS01) Present(_ context.Context, _, fqdn, value string) error {
	if m.Records == nil {
		m.Records = make(map[string][]string)
	}
	fqdn = normalizeFQDN(fqdn)
	m.Records[fqdn] = append(m.Records[fqdn], value)
	return nil
}

// CleanUp removes one TXT value.
func (m *MemoryDNS01) CleanUp(_ context.Context, _, fqdn, value string) error {
	fqdn = normalizeFQDN(fqdn)
	vals := m.Records[fqdn]
	out := vals[:0]
	for _, v := range vals {
		if v != value {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		delete(m.Records, fqdn)
	} else {
		m.Records[fqdn] = out
	}
	return nil
}

func normalizeFQDN(fqdn string) string {
	fqdn = strings.TrimSpace(fqdn)
	if fqdn != "" && !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	return strings.ToLower(fqdn)
}

// WebhookDNS01 calls a user-provided HTTP webhook for Present/CleanUp.
// POST body: {"action":"present|cleanup","domain":"...","fqdn":"...","value":"..."}
type WebhookDNS01 struct {
	URL    string
	Client HTTPDoer
	// SkipURLValidate disables SSRF checks (unit tests with httptest only).
	SkipURLValidate bool
}

// HTTPDoer is a minimal HTTP client (for tests).
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Present implements DNS01Presenter via webhook.
func (w *WebhookDNS01) Present(ctx context.Context, domain, fqdn, value string) error {
	return w.post(ctx, "present", domain, fqdn, value)
}

// CleanUp implements DNS01Presenter via webhook.
func (w *WebhookDNS01) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	return w.post(ctx, "cleanup", domain, fqdn, value)
}

func (w *WebhookDNS01) post(ctx context.Context, action, domain, fqdn, value string) error {
	if w.URL == "" {
		return fmt.Errorf("dns webhook URL required")
	}
	return postDNSWebhookOpts(ctx, w.Client, w.URL, action, domain, fqdn, value, w.SkipURLValidate)
}
