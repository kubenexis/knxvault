// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"context"
	"fmt"
)

// RegistryAdapter wraps the ssh engine for engine.Registry registration.
type RegistryAdapter struct {
	*Engine
}

// NewRegistryAdapter constructs a SecretEngine adapter for the ssh engine.
func NewRegistryAdapter(engine *Engine) RegistryAdapter {
	return RegistryAdapter{Engine: engine}
}

// Put is not supported; ssh credentials are generated via roles.
func (a RegistryAdapter) Put(_ context.Context, _ string, _ map[string]any) error {
	return fmt.Errorf("ssh engine does not support direct put")
}

// Get is not supported; ssh credentials are generated via roles.
func (a RegistryAdapter) Get(_ context.Context, _ string) (map[string]any, error) {
	return nil, fmt.Errorf("ssh engine does not support direct get")
}
