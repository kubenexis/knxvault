// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package memzero_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/crypto/memzero"
)

func TestBytesZeroesSlice(t *testing.T) {
	buf := []byte("super-secret-key-material")
	memzero.Bytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d not zeroed", i)
		}
	}
}
