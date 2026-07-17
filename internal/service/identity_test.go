// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestIdentityResolveLoginMergesGroupPolicies(t *testing.T) {
	svc := service.NewIdentityService(auditsvc.NewService(memory.NewAuditRepository()))
	ctx := context.Background()
	ent, err := svc.CreateEntity(ctx, "alice", []string{"reader"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateAlias(ctx, ent.ID, "oidc", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateGroup(ctx, "admins", []string{ent.ID}, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	eid, pols, err := svc.ResolveLogin(ctx, "oidc", "alice@example.com", []string{"base"})
	if err != nil {
		t.Fatal(err)
	}
	if eid != ent.ID {
		t.Fatalf("entity %s", eid)
	}
	want := map[string]bool{"base": true, "reader": true, "admin": true}
	for _, p := range pols {
		delete(want, p)
	}
	if len(want) != 0 {
		t.Fatalf("missing policies %v got %v", want, pols)
	}
}

func TestIdentityDisabledEntity(t *testing.T) {
	svc := service.NewIdentityService(auditsvc.NewService(memory.NewAuditRepository()))
	ctx := context.Background()
	ent, _ := svc.CreateEntity(ctx, "bob", nil, nil)
	_, _ = svc.CreateAlias(ctx, ent.ID, "k8s", "ns:sa")
	_ = svc.SetEntityDisabled(ctx, ent.ID, true)
	if _, _, err := svc.ResolveLogin(ctx, "k8s", "ns:sa", []string{"p"}); err == nil {
		t.Fatal("expected disabled error")
	}
}
