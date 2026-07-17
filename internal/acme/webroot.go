// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WebrootHTTP01 presents HTTP-01 challenges as files under a web root:
// <root>/.well-known/acme-challenge/<token>
type WebrootHTTP01 struct {
	Root string
}

// Present writes the challenge response file.
func (w *WebrootHTTP01) Present(_ context.Context, _, token, keyAuth string) error {
	if err := validateHTTP01Token(token); err != nil {
		return err
	}
	root := strings.TrimSpace(w.Root)
	if root == "" {
		return fmt.Errorf("http-01 webroot is required")
	}
	dir := filepath.Join(root, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, token)
	return os.WriteFile(path, []byte(keyAuth), 0o644)
}

// CleanUp removes the challenge file.
func (w *WebrootHTTP01) CleanUp(_ context.Context, _, token, _ string) error {
	if err := validateHTTP01Token(token); err != nil {
		return nil
	}
	root := strings.TrimSpace(w.Root)
	if root == "" {
		return nil
	}
	path := filepath.Join(root, ".well-known", "acme-challenge", token)
	_ = os.Remove(path)
	return nil
}
