package acme_test

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubenexis/knxvault/internal/acme"
)

func TestAccountKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account.key")
	store := acme.AccountKeyFile{Path: path}
	key, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("perms %v", info.Mode())
	}
	key2, err := store.Load()
	if err != nil || key2 == nil {
		t.Fatal(err)
	}
	if !key.(*ecdsa.PrivateKey).Equal(key2.(*ecdsa.PrivateKey)) {
		t.Fatal("mismatch")
	}
}

func TestAccountKeyFileEmptyPath(t *testing.T) {
	var a acme.AccountKeyFile
	if _, err := a.Load(); err == nil {
		t.Fatal("expected error")
	}
}
