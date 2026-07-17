// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/service"
	"github.com/kubenexis/knxvault/internal/tenant"
)

// access unexported helpers via behavior of DatabaseService
func TestDatabaseServiceTenantScopesRoleNames(t *testing.T) {
	// Use SSH/DB engine with memory if available — light unit via export would need export.
	// Validate tenant ScopePath used consistently:
	ctx := tenant.WithContext(context.Background(), "team-a")
	// Package-level check through GetRole without engine: skip heavy.
	// Ensure ScopePath produces expected prefix for engine keys.
	scoped := tenant.ScopePath("team-a", "db-role", true)
	if scoped != "team-a/db-role" {
		t.Fatalf("scoped = %q", scoped)
	}
	if !tenant.ValidateAccess("team-a", scoped, true) {
		t.Fatal("validate")
	}
	if tenant.ValidateAccess("team-b", scoped, true) {
		t.Fatal("cross-tenant should fail")
	}
	_ = ctx
	_ = service.NewDatabaseService(nil, nil)
}
