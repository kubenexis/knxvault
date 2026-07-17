// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package shamir_test

import (
	"bytes"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto/shamir"
)

func TestSplitCombine(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 5 {
		t.Fatalf("shares = %d", len(shares))
	}
	// Any 3
	got, err := shamir.Combine(shares[0:3])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("got %x want %x", got, secret)
	}
	// Different 3
	got, err = shamir.Combine([][]byte{shares[1], shares[3], shares[4]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("combine mismatch")
	}
	// 2 shares insufficient / wrong secret
	got2, err := shamir.Combine(shares[0:2])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got2, secret) {
		t.Fatal("2 shares should not recover secret")
	}
}

func TestSplitInvalidParams(t *testing.T) {
	if _, err := shamir.Split([]byte("x"), 2, 3); err == nil {
		t.Fatal("expected t>n error")
	}
}
