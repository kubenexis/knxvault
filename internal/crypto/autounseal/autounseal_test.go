package autounseal_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto/autounseal"
)

func TestFileProviderUnsealKey(t *testing.T) {
	key := []byte("test-unseal-key-32-bytes-long!!")
	path := filepath.Join(t.TempDir(), "unseal.key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &autounseal.FileProvider{Path: path}
	got, err := p.UnsealKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Fatalf("got %q want %q", got, key)
	}
}
