// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package tenantrepo_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	tenantrepo "github.com/kubenexis/knxvault/internal/repository/tenant"
)

func TestWrapSecretDisabledReturnsInner(t *testing.T) {
	inner := memory.NewSecretRepository()
	got := tenantrepo.WrapSecret(inner, "ns-a", false)
	if got != inner {
		t.Fatal("disabled wrap should return inner")
	}
	if tenantrepo.WrapSecret(nil, "ns-a", true) != nil {
		t.Fatal("nil inner should stay nil")
	}
}

func TestWrapSecretScopesPaths(t *testing.T) {
	ctx := context.Background()
	inner := memory.NewSecretRepository()
	repo := tenantrepo.WrapSecret(inner, "team-a", true)

	sv := &domainsecrets.SecretVersion{
		ID:        uuid.New(),
		Path:      "app/db",
		Version:   1,
		DataEnc:   []byte("cipher"),
		DEKEnc:    []byte("dek"),
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.SaveVersion(ctx, sv); err != nil {
		t.Fatal(err)
	}
	if sv.Path != "team-a/app/db" {
		t.Fatalf("scoped path = %q", sv.Path)
	}

	got, err := repo.GetLatest(ctx, "app/db")
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "team-a/app/db" {
		t.Fatalf("get path = %q", got.Path)
	}

	// Direct access to wrong tenant prefix is rejected by ValidateAccess after ScopePath:
	// ScopePath("team-a", "team-b/x") => "team-a/team-b/x" which is allowed for team-a.
	// Cross-tenant isolation is that callers only get their prefix; verify list under scoped prefix.
	list, err := repo.ListByPath(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d", len(list))
	}
}
