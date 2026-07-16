package app_test

import (
	"bytes"
	"testing"

	"github.com/kubenexis/knxvault/internal/app"
)

func TestSealStateRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	seal := app.NewSealState(key)
	// W50-03: unseal key present ⇒ start sealed until Unseal.
	if !seal.Sealed() {
		t.Fatal("expected sealed initially when unseal key configured")
	}
	if !seal.Unseal(key) {
		t.Fatal("expected valid unseal")
	}
	if seal.Sealed() {
		t.Fatal("expected unsealed after unseal")
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

func TestSealStateDoubleSealAndIdempotentUnseal(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	seal := app.NewSealState(key)
	seal.Seal()
	seal.Seal()
	if !seal.Sealed() {
		t.Fatal("expected sealed after double seal")
	}
	if !seal.Unseal(key) {
		t.Fatal("expected valid unseal")
	}
	if !seal.Unseal(key) {
		t.Fatal("expected idempotent unseal to succeed when already unsealed")
	}
	if seal.Sealed() {
		t.Fatal("expected unsealed")
	}
}

func TestSealStateNilSafe(t *testing.T) {
	var seal *app.SealState
	if seal.Sealed() {
		t.Fatal("nil seal should report unsealed")
	}
	seal.Seal()
	if seal.Unseal(nil) {
		t.Fatal("nil seal should reject unseal")
	}
}

func TestSealStateRejectsWrongKeyLength(t *testing.T) {
	key := make([]byte, 32)
	seal := app.NewSealState(key)
	seal.Seal()
	if seal.Unseal(key[:16]) {
		t.Fatal("expected wrong-length key to fail")
	}
}
