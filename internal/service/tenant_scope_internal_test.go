// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/tenant"
)

func TestScopeResourceNameTenantMode(t *testing.T) {
	ctx := tenant.WithContext(context.Background(), "team-a")
	got, err := scopeResourceName(ctx, true, "db-role")
	if err != nil {
		t.Fatal(err)
	}
	if got != "team-a/db-role" {
		t.Fatalf("got %q", got)
	}
	// Without tenant mode, name is unchanged.
	got, err = scopeResourceName(ctx, false, "db-role")
	if err != nil || got != "db-role" {
		t.Fatalf("off mode: %q err=%v", got, err)
	}
	// Tenant mode without namespace fails closed.
	_, err = scopeResourceName(context.Background(), true, "db-role")
	if err == nil {
		t.Fatal("expected error without namespace")
	}
}

func TestAssertTenantAccess(t *testing.T) {
	ctx := tenant.WithContext(context.Background(), "team-a")
	if err := assertTenantAccess(ctx, true, "team-a/db-role"); err != nil {
		t.Fatal(err)
	}
	if err := assertTenantAccess(ctx, true, "team-b/db-role"); err == nil {
		t.Fatal("cross-tenant should fail")
	}
	if err := assertTenantAccess(ctx, false, "team-b/db-role"); err != nil {
		t.Fatal(err)
	}
}

func TestAssertTenantLeaseAccess(t *testing.T) {
	ctx := context.Background()
	if err := assertTenantLeaseAccess(ctx, false, "any"); err != nil {
		t.Fatal(err)
	}
	if err := assertTenantLeaseAccess(ctx, true, "ns.lease"); err == nil {
		t.Fatal("expected namespace required")
	}
	ctx = tenant.WithContext(ctx, "ns-a")
	if err := assertTenantLeaseAccess(ctx, true, "ns-a.lease1"); err != nil {
		t.Fatal(err)
	}
	if err := assertTenantLeaseAccess(ctx, true, "ns-b.lease1"); err == nil {
		t.Fatal("expected cross-tenant deny")
	}
	// Legacy slash-prefixed IDs still accepted for same tenant.
	if err := assertTenantLeaseAccess(ctx, true, "ns-a/legacy"); err != nil {
		t.Fatal(err)
	}
}
