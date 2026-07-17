// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package acme_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/acme"
)

func TestW78_IsLoopbackDirectoryURL(t *testing.T) {
	if !acme.IsLoopbackDirectoryURL("https://127.0.0.1:14000/dir") {
		t.Fatal("127.0.0.1")
	}
	if !acme.IsLoopbackDirectoryURL("http://localhost:14000/dir") {
		t.Fatal("localhost")
	}
	if acme.IsLoopbackDirectoryURL("http://169.254.169.254/") {
		t.Fatal("metadata must not be loopback")
	}
	if acme.IsLoopbackDirectoryURL("https://acme-v02.api.letsencrypt.org/directory") {
		t.Fatal("LE must not be loopback")
	}
}

func TestW78_ValidateDirectoryBlocksPrivate(t *testing.T) {
	if err := acme.ValidateDirectoryURL("http://10.0.0.1/dir"); err == nil {
		t.Fatal("private IP")
	}
	if err := acme.ValidateDirectoryURL("http://169.254.169.254/"); err == nil {
		t.Fatal("metadata")
	}
}
