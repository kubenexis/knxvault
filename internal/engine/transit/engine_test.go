package transit_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto"
	"github.com/kubenexis/knxvault/internal/engine/transit"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func testCrypto(t *testing.T) *crypto.Service {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	svc, err := crypto.NewService(key)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestTransitEncryptDecryptRotate(t *testing.T) {
	e := transit.NewEngine(memory.NewSecretRepository(), testCrypto(t))
	ctx := context.Background()
	meta, err := e.CreateKey(ctx, "app")
	if err != nil || meta.LatestVersion != 1 {
		t.Fatalf("CreateKey: %v %+v", err, meta)
	}
	ct, err := e.Encrypt(ctx, "app", []byte("hello"), 0)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := e.Decrypt(ctx, "app", ct)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("Decrypt: %v %q", err, pt)
	}
	if _, err := e.RotateKey(ctx, "app"); err != nil {
		t.Fatal(err)
	}
	// old ciphertext still works
	pt2, err := e.Decrypt(ctx, "app", ct)
	if err != nil || string(pt2) != "hello" {
		t.Fatalf("decrypt after rotate: %v", err)
	}
	ct2, err := e.Rewrap(ctx, "app", ct)
	if err != nil {
		t.Fatal(err)
	}
	pt3, err := e.Decrypt(ctx, "app", ct2)
	if err != nil || string(pt3) != "hello" {
		t.Fatalf("rewrap: %v", err)
	}
}

func TestTransitHMACSignVerify(t *testing.T) {
	e := transit.NewEngine(nil, testCrypto(t))
	ctx := context.Background()
	if _, err := e.CreateKey(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	sig, err := e.Sign(ctx, "h", []byte("msg"), 0)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := e.Verify(ctx, "h", []byte("msg"), sig)
	if err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	ok, _ = e.Verify(ctx, "h", []byte("other"), sig)
	if ok {
		t.Fatal("expected verify fail")
	}
}

func TestTransitDuplicateKey(t *testing.T) {
	e := transit.NewEngine(nil, testCrypto(t))
	ctx := context.Background()
	if _, err := e.CreateKey(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CreateKey(ctx, "k"); err == nil {
		t.Fatal("expected conflict")
	}
}
