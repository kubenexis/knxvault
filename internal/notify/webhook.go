// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package notify delivers outbound webhook notifications.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
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
func NewWebhook(url string) *Webhook {
	if url == "" {
		return nil
	}
	return &Webhook{
		url: url,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Send posts an event asynchronously when URL is configured.
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
