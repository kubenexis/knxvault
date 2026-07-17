// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"sync"
)

// Registry maps engine names to SecretEngine implementations (LLD §4.B.4).
type Registry struct {
	mu      sync.RWMutex
	engines map[string]SecretEngine
}

// NewRegistry constructs an empty engine registry.
func NewRegistry() *Registry {
	return &Registry{engines: make(map[string]SecretEngine)}
}

// Register adds an engine. Panics on duplicate names during startup wiring.
func (r *Registry) Register(engine SecretEngine) {
	if engine == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	name := engine.Name()
	if _, exists := r.engines[name]; exists {
		panic(fmt.Sprintf("duplicate secret engine %q", name))
	}
	r.engines[name] = engine
}

// Get returns an engine by name.
func (r *Registry) Get(name string) (SecretEngine, bool) {
	return r.lookup(name)
}

// List returns registered engine names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.engines))
	for name := range r.engines {
		out = append(out, name)
	}
	return out
}

// Put delegates to a named engine.
func (r *Registry) Put(ctx context.Context, name, path string, data map[string]any) error {
	engine, ok := r.lookup(name)
	if !ok {
		return fmt.Errorf("unknown secret engine %q", name)
	}
	return engine.Put(ctx, path, data)
}

// GetSecret delegates to a named engine.
func (r *Registry) GetSecret(ctx context.Context, name, path string) (map[string]any, error) {
	engine, ok := r.lookup(name)
	if !ok {
		return nil, fmt.Errorf("unknown secret engine %q", name)
	}
	return engine.Get(ctx, path)
}

func (r *Registry) lookup(name string) (SecretEngine, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	engine, ok := r.engines[name]
	return engine, ok
}
