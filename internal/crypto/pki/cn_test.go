// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto/pki"
)

func TestValidateCommonName(t *testing.T) {
	if err := pki.ValidateCommonName("good.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := pki.ValidateCommonName("evil/O=Attacker"); err == nil {
		t.Fatal("expected reject slash")
	}
	if err := pki.ValidateCommonName(""); err == nil {
		t.Fatal("expected reject empty")
	}
}
