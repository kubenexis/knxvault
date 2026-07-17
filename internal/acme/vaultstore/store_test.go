package vaultstore_test

import (
	"errors"
	"testing"

	"github.com/kubenexis/knxvault/internal/acme/vaultstore"
)

func TestNotImplemented(t *testing.T) {
	s := vaultstore.New(vaultstore.Config{Addr: "http://127.0.0.1:8200"})
	if err := s.LoadAccountKey(); !errors.Is(err, vaultstore.ErrNotImplemented) {
		t.Fatalf("%v", err)
	}
	if err := s.SaveAccountKey(); !errors.Is(err, vaultstore.ErrNotImplemented) {
		t.Fatalf("%v", err)
	}
}
