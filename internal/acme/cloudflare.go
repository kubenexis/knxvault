// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudflareDNS01 implements DNS-01 via Cloudflare API v4 (token auth).
// No extra Go dependency — raw HTTPS only (Apache-compatible stack).
type CloudflareDNS01 struct {
	APIToken string
	// ZoneID optional; when empty, zones are listed and matched by domain suffix.
	ZoneID string
	Client HTTPDoer
	Base   string // default https://api.cloudflare.com/client/v4
}

type cfResult struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

// Present creates a TXT record.
func (c *CloudflareDNS01) Present(ctx context.Context, domain, fqdn, value string) error {
	zoneID, err := c.resolveZone(ctx, domain)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(fqdn, ".")
	payload := map[string]any{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     120,
	}
	return c.api(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", payload, nil)
}

// CleanUp deletes matching TXT records.
func (c *CloudflareDNS01) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	zoneID, err := c.resolveZone(ctx, domain)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(fqdn, ".")
	var list struct {
		Result []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Content string `json:"content"`
			Type    string `json:"type"`
		} `json:"result"`
	}
	path := fmt.Sprintf("/zones/%s/dns_records?type=TXT&name=%s", zoneID, name)
	if err := c.api(ctx, http.MethodGet, path, nil, &list); err != nil {
		return err
	}
	for _, rec := range list.Result {
		if rec.Content != value {
			continue
		}
		if err := c.api(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+rec.ID, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *CloudflareDNS01) resolveZone(ctx context.Context, domain string) (string, error) {
	if c.ZoneID != "" {
		return c.ZoneID, nil
	}
	var list struct {
		Result []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := c.api(ctx, http.MethodGet, "/zones?per_page=50", nil, &list); err != nil {
		return "", err
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	var best string
	var bestLen int
	for _, z := range list.Result {
		zn := strings.ToLower(z.Name)
		if domain == zn || strings.HasSuffix(domain, "."+zn) {
			if len(zn) > bestLen {
				best = z.ID
				bestLen = len(zn)
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("cloudflare: no zone found for domain %q", domain)
	}
	return best, nil
}

func (c *CloudflareDNS01) api(ctx context.Context, method, path string, payload any, out any) error {
	if c.APIToken == "" {
		return fmt.Errorf("cloudflare API token required")
	}
	base := c.Base
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	client := c.Client
	if client == nil {
		// W80-01: never use a bare http.Client (env proxy / SSRF class).
		client = SafeHTTPClient(30 * time.Second)
	}
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var wrap cfResult
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return fmt.Errorf("cloudflare decode: %w body=%s", err, string(raw))
	}
	if !wrap.Success || resp.StatusCode >= 300 {
		msg := resp.Status
		if len(wrap.Errors) > 0 {
			msg = wrap.Errors[0].Message
		}
		return fmt.Errorf("cloudflare API: %s", msg)
	}
	if out != nil && len(wrap.Result) > 0 {
		// list endpoints nest result differently — re-unmarshal full body when needed
		if err := json.Unmarshal(raw, out); err != nil {
			// single-object result
			return json.Unmarshal(wrap.Result, out)
		}
	}
	return nil
}
