// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package auth

import "testing"

func TestParseBindResponseOK(t *testing.T) {
	resp := []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x61, 0x07,
		0x0a, 0x01, 0x00,
		0x04, 0x00,
		0x04, 0x00,
	}
	if err := parseBindResponse(resp, 1); err != nil {
		t.Fatal(err)
	}
}

func TestParseBindResponseRejectsLooseMagic(t *testing.T) {
	// Contains 0x0a 0x01 0x00 but not a valid BindResponse structure.
	resp := []byte{0x30, 0x05, 0x04, 0x03, 0x0a, 0x01, 0x00}
	if err := parseBindResponse(resp, 1); err == nil {
		t.Fatal("expected reject")
	}
}

func TestParseBindResponseResultCodeFail(t *testing.T) {
	resp := []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x61, 0x07,
		0x0a, 0x01, 0x31, // invalid credentials (49)
		0x04, 0x00,
		0x04, 0x00,
	}
	if err := parseBindResponse(resp, 1); err == nil {
		t.Fatal("expected fail")
	}
}
