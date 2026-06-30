package app_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/app"
)

func TestSealStateRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	seal := app.NewSealState(key)
	if seal.Sealed() {
		t.Fatal("expected unsealed initially")
	}
	seal.Seal()
	if !seal.Sealed() {
		t.Fatal("expected sealed")
	}
	wrong := make([]byte, 32)
	for i := range wrong {
		wrong[i] = 0xFF
	}
	if seal.Unseal(wrong) {
		t.Fatal("expected invalid unseal to fail")
	}
	if !seal.Unseal(key) {
		t.Fatal("expected valid unseal")
	}
	if seal.Sealed() {
		t.Fatal("expected unsealed after unseal")
	}
}
