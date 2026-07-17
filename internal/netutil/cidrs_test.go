// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package netutil_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/netutil"
)

func TestIPAllowed(t *testing.T) {
	nets, err := netutil.ParseCIDRs([]string{"10.0.0.0/8", "192.168.1.5"})
	if err != nil {
		t.Fatal(err)
	}
	if !netutil.IPAllowed("10.1.2.3", nets) {
		t.Fatal("10.x")
	}
	if !netutil.IPAllowed("192.168.1.5", nets) {
		t.Fatal("exact")
	}
	if netutil.IPAllowed("8.8.8.8", nets) {
		t.Fatal("public denied")
	}
	if !netutil.IPAllowed("8.8.8.8", nil) {
		t.Fatal("empty allowlist allows all")
	}
}
