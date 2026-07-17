// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/engine"
)

type stubEngine struct {
	name string
}

func (s stubEngine) Name() string { return s.name }
func (s stubEngine) Put(context.Context, string, map[string]any) error {
	return nil
}
func (s stubEngine) Get(context.Context, string) (map[string]any, error) {
	return map[string]any{"ok": true}, nil
}

func TestRegistryRegisterGet(t *testing.T) {
	reg := engine.NewRegistry()
	reg.Register(stubEngine{name: "kv"})
	got, ok := reg.Get("kv")
	if !ok {
		t.Fatal("expected engine to be registered")
	}
	if got.Name() != "kv" {
		t.Fatalf("Name() = %q, want kv", got.Name())
	}
}
