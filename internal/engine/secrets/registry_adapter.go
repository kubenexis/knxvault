// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets

import "context"

// RegistryAdapter wraps KVV2Engine for engine.Registry registration.
type RegistryAdapter struct {
	*KVV2Engine
}

// NewRegistryAdapter constructs a SecretEngine adapter for the KV engine.
func NewRegistryAdapter(engine *KVV2Engine) RegistryAdapter {
	return RegistryAdapter{KVV2Engine: engine}
}

// Put stores a secret using default write options.
func (a RegistryAdapter) Put(ctx context.Context, path string, data map[string]any) error {
	_, err := a.KVV2Engine.Put(ctx, path, data, PutOptions{})
	return err
}

// Get returns decrypted secret data from the latest version.
func (a RegistryAdapter) Get(ctx context.Context, path string) (map[string]any, error) {
	result, err := a.KVV2Engine.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}
