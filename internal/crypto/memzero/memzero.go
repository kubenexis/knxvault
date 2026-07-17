// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

// Package memzero securely zeroes sensitive byte slices.
package memzero

import "runtime"

// Bytes overwrites b with zeros and keeps the slice alive until zeroing completes.
func Bytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
