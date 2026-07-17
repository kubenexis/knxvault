// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package autounseal_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto/autounseal"
)

func TestSealDecryptRoundTrip(t *testing.T) {
	kek := make([]byte, 32)
	unseal := make([]byte, 32)
	_, _ = rand.Read(kek)
	_, _ = rand.Read(unseal)
	ct, err := autounseal.SealUnsealKey(unseal, kek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := autounseal.DecryptUnsealKey(autounseal.Config{
		Provider:   "aes-kek",
		Ciphertext: ct,
		KEK:        base64.StdEncoding.EncodeToString(kek),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(unseal) {
		t.Fatal("mismatch")
	}
}

func TestUnknownProvider(t *testing.T) {
	if _, err := autounseal.DecryptUnsealKey(autounseal.Config{Provider: "aws"}); err == nil {
		t.Fatal("expected error")
	}
}
