// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/engine/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestW85_KVRejectsReservedInternalPaths(t *testing.T) {
	mk := make([]byte, 32)
	_, _ = rand.Read(mk)
	svc, err := crypto.NewService(mk)
	if err != nil {
		t.Fatal(err)
	}
	eng := secrets.NewKVV2Engine(memory.NewSecretRepository(), svc)
	ctx := context.Background()
	for _, path := range []string{
		"cubbyhole/abc/response",
		"sys/wrapping/meta/x",
		"database/creds/role/lease",
		"ssh/creds/role/lease",
		"transit/keys/mykey",
		"sys/internal/approles",
	} {
		if _, err := eng.Get(ctx, path); err == nil {
			t.Fatalf("expected deny get %q", path)
		}
		if _, err := eng.Put(ctx, path, map[string]any{"k": "v"}, secrets.PutOptions{}); err == nil {
			t.Fatalf("expected deny put %q", path)
		}
	}
	// Normal path still works.
	if _, err := eng.Put(ctx, "app/db", map[string]any{"pw": "x"}, secrets.PutOptions{}); err != nil {
		t.Fatal(err)
	}
}
