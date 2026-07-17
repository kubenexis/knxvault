// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type dnsWebhookBody struct {
	Action string `json:"action"`
	Domain string `json:"domain"`
	FQDN   string `json:"fqdn"`
	Value  string `json:"value"`
}

func postDNSWebhookOpts(ctx context.Context, client HTTPDoer, rawURL, action, domain, fqdn, value string, skipValidate bool) error {
	if !skipValidate {
		if err := ValidateOutboundURL(rawURL); err != nil {
			return fmt.Errorf("dns webhook url: %w", err)
		}
	}
	if client == nil {
		client = SafeHTTPClient(30 * time.Second)
	}
	body, err := json.Marshal(dnsWebhookBody{
		Action: action,
		Domain: domain,
		FQDN:   fqdn,
		Value:  value,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("dns webhook %s: status %d: %s", action, resp.StatusCode, string(b))
	}
	return nil
}
