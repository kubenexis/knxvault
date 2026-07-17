// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"encoding/base64"
	"testing"

	"github.com/kubenexis/knxvault/internal/app"
	"github.com/kubenexis/knxvault/internal/crypto/shamir"
)

func TestSealMultiShareUnseal(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	shares, err := shamir.Split(key, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	seal := app.NewSealState(key)
	seal.SetUnsealThreshold(2)
	if !seal.Sealed() {
		t.Fatal("expected sealed")
	}
	ok, have, need, msg := seal.SubmitShare(shares[0])
	if ok || have != 1 || need != 2 || msg != "" {
		t.Fatalf("first share: ok=%v have=%d need=%d msg=%q", ok, have, need, msg)
	}
	ok, have, need, msg = seal.SubmitShare(shares[1])
	if !ok || msg != "" {
		t.Fatalf("second share: ok=%v have=%d need=%d msg=%q", ok, have, need, msg)
	}
	if seal.Sealed() {
		t.Fatal("expected unsealed after threshold shares")
	}
	_ = base64.StdEncoding.EncodeToString(shares[0])
}

func TestSealMultiShareRejectsWrongShares(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xab
	}
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0xcd
	}
	badShares, err := shamir.Split(other, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	seal := app.NewSealState(key)
	seal.SetUnsealThreshold(2)
	_, _, _, _ = seal.SubmitShare(badShares[0])
	ok, _, _, msg := seal.SubmitShare(badShares[1])
	if ok {
		t.Fatal("wrong secret shares must not unseal")
	}
	if msg == "" {
		t.Fatal("expected error message")
	}
}
