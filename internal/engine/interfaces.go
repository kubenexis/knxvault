// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package engine defines secret and PKI engine interfaces (LLD §4).
package engine

import "context"

// SecretEngine is implemented by KV and dynamic secret backends.
type SecretEngine interface {
	Name() string
	Put(ctx context.Context, path string, data map[string]any) error
	Get(ctx context.Context, path string) (map[string]any, error)
}
