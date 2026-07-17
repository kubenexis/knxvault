package cubbyhole_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/engine/secrets/cubbyhole"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func testCrypto(t *testing.T) *crypto.Service {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	svc, err := crypto.NewService(key)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestCubbyholePutGetDelete(t *testing.T) {
	e := cubbyhole.NewEngine(memory.NewSecretRepository(), testCrypto(t))
	ctx := context.Background()
	if err := e.Put(ctx, "tok1", "secret", map[string]any{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	data, err := e.Get(ctx, "tok1", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if data["k"] != "v" {
		t.Fatalf("data=%v", data)
	}
	// other token cannot read (different path)
	if _, err := e.Get(ctx, "tok2", "secret"); err == nil {
		t.Fatal("expected miss for other token")
	}
	if err := e.Delete(ctx, "tok1", "secret"); err != nil {
		t.Fatal(err)
	}
}

func TestCubbyholeWipeToken(t *testing.T) {
	e := cubbyhole.NewEngine(memory.NewSecretRepository(), testCrypto(t))
	ctx := context.Background()
	_ = e.Put(ctx, "tok", "a", map[string]any{"x": 1})
	_ = e.Put(ctx, "tok", "b", map[string]any{"y": 2})
	if err := e.WipeToken(ctx, "tok"); err != nil {
		t.Fatal(err)
	}
}

func TestCubbyholeRejectsBadPath(t *testing.T) {
	e := cubbyhole.NewEngine(memory.NewSecretRepository(), testCrypto(t))
	if err := e.Put(context.Background(), "t", "../x", map[string]any{"a": 1}); err == nil {
		t.Fatal("expected path error")
	}
}
