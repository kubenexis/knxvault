// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"bytes"
	"os"
	"testing"
	"time"

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
	// W50-28: wait out progressive backoff before valid unseal.
	if wait := seal.UnsealRetryAfter(); wait > 0 {
		time.Sleep(wait + 20*time.Millisecond)
	}
	if !seal.Unseal(key) {
		t.Fatal("expected valid unseal")
	}
	if seal.Sealed() {
		t.Fatal("expected unsealed after unseal")
	}
}

func TestSealStateFileNeverAutoUnseals(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	dir := t.TempDir()
	path := dir + "/seal.state"
	if err := os.WriteFile(path, []byte("unsealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	seal := app.NewSealState(key)
	seal.SetStateFile(path)
	if !seal.Sealed() {
		t.Fatal("disk 'unsealed' marker must not open vault without cryptographic unseal")
	}
	if !seal.Unseal(key) {
		t.Fatal("cryptographic unseal should succeed")
	}
	if seal.Sealed() {
		t.Fatal("expected unsealed after Unseal(key)")
	}
}

func TestSealStateUnsealBackoff(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	seal := app.NewSealState(key)
	wrong := make([]byte, 32)
	if seal.Unseal(wrong) {
		t.Fatal("expected fail")
	}
	// Immediate retry while backoff active should fail even with correct key.
	if seal.Unseal(key) {
		t.Fatal("expected backoff to block unseal")
	}
	if seal.UnsealRetryAfter() <= 0 {
		t.Fatal("expected positive retry-after")
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
