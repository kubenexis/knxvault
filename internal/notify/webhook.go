// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package notify delivers outbound webhook notifications.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kubenexis/knxvault/internal/acme"
)

// Event is a webhook payload.
type Event struct {
	Event    string         `json:"event"`
	Path     string         `json:"path,omitempty"`
	LeaseID  string         `json:"lease_id,omitempty"`
	Severity string         `json:"severity,omitempty"`
	Detector string         `json:"detector,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// Webhook posts JSON events to a configured URL.
type Webhook struct {
	url    string
	client *http.Client
}

// NewWebhook constructs a webhook notifier.
// URL must pass SSRF checks (public http/https). Empty URL returns nil (disabled).
// Invalid URL returns nil and is treated as disabled — callers that require webhooks
// should validate with ValidateURL first (deps does this for production configs).
func NewWebhook(url string) *Webhook {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil
	}
	if err := ValidateURL(url); err != nil {
		return nil
	}
	return &Webhook{
		url:    url,
		client: acme.SafeHTTPClient(10 * time.Second),
	}
}

// ValidateURL rejects SSRF-prone webhook destinations (shared with ACME outbound policy).
func ValidateURL(raw string) error {
	return acme.ValidateOutboundURL(raw)
}

// NewWebhookWithClient is for tests that need loopback httptest destinations.
func NewWebhookWithClient(url string, client *http.Client) *Webhook {
	if strings.TrimSpace(url) == "" {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Webhook{url: url, client: client}
}

// Send posts an event when URL is configured.
func (w *Webhook) Send(ctx context.Context, event Event) error {
	if w == nil || w.url == "" {
		return nil
	}
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}
