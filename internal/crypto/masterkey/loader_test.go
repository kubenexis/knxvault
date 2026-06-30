package masterkey_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto/masterkey"
)

func TestLoadFromEnv(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("KNXVAULT_MASTER_KEY_FILE", "")
	t.Setenv("KNXVAULT_MASTER_KEY", base64.StdEncoding.EncodeToString(key))

	got, err := masterkey.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(got) != string(key) {
		t.Fatal("key mismatch")
	}
}

func TestLoadFromFile(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(255 - i)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KNXVAULT_MASTER_KEY", "")
	t.Setenv("KNXVAULT_MASTER_KEY_FILE", path)

	got, err := masterkey.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(got) != string(key) {
		t.Fatal("key mismatch")
	}
}

func TestLoadMissing(t *testing.T) {
	t.Setenv("KNXVAULT_MASTER_KEY", "")
	t.Setenv("KNXVAULT_MASTER_KEY_FILE", "")

	_, err := masterkey.Load()
	if err == nil {
		t.Fatal("expected error when master key unset")
	}
}
