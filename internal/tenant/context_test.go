// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package tenant_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/tenant"
)

func TestScopeAndValidateLeaseID(t *testing.T) {
	id := tenant.ScopeLeaseID("ns-a", "lease1", true)
	if id != "ns-a/lease1" {
		t.Fatalf("got %s", id)
	}
	if !tenant.ValidateLeaseIDAccess("ns-a", id, true) {
		t.Fatal("same tenant")
	}
	if tenant.ValidateLeaseIDAccess("ns-b", id, true) {
		t.Fatal("cross tenant")
	}
	if tenant.ScopeLeaseID("ns-a", "lease1", false) != "lease1" {
		t.Fatal("disabled")
	}
}
