// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package vaultiface

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// ensureToken refreshes the vault client token via Kubernetes SA login when configured.
// Lab host processes fall back to a static bootstrap token when the SA file is absent.
func (h *HTTPAPI) ensureToken(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.C.Token != "" && time.Now().Before(h.tokenTTL) {
		return nil
	}
	if h.saPath == "" {
		if h.C.Token == "" {
			return fmt.Errorf("no vault token configured")
		}
		h.tokenTTL = time.Now().Add(time.Hour)
		return nil
	}
	b, err := os.ReadFile(h.saPath) //nolint:gosec // path from operator config
	if err != nil {
		if h.C.Token != "" {
			h.tokenTTL = time.Now().Add(time.Hour)
			return nil
		}
		return fmt.Errorf("read SA token: %w", err)
	}
	jwt := strings.TrimSpace(string(b))
	if jwt == "" {
		return fmt.Errorf("empty SA token")
	}
	if _, err := h.C.LoginKubernetes(ctx, h.role, jwt); err != nil {
		if h.C.Token != "" {
			h.tokenTTL = time.Now().Add(5 * time.Minute)
			return nil
		}
		return fmt.Errorf("kubernetes login: %w", err)
	}
	h.tokenTTL = time.Now().Add(30 * time.Minute)
	return nil
}
