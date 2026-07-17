// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
	secretsengine "github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestKVV2DeleteHidesLatestFromGet(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	cs, err := crypto.NewService(key)
	if err != nil {
		t.Fatal(err)
	}
	repo := memory.NewSecretRepository()
	e := secretsengine.NewKVV2Engine(repo, cs)
	ctx := context.Background()
	put, err := e.Put(ctx, "app/db", map[string]any{"pw": "s3cret"}, secretsengine.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if put.Version < 1 {
		t.Fatalf("version %d", put.Version)
	}
	got, err := e.Get(ctx, "app/db")
	if err != nil || got.Data["pw"] != "s3cret" {
		t.Fatalf("get before delete: %v %+v", err, got)
	}
	if err := e.Delete(ctx, "app/db"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Get(ctx, "app/db"); err == nil {
		t.Fatal("expected get after soft-delete to fail")
	}
}
