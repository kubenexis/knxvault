// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestPolicyServiceSaveAndLoad(t *testing.T) {
	policies := memory.NewPolicyRepository()
	roles := memory.NewRoleRepository()
	rbac := auth.NewRBAC()
	svc := service.NewPolicyService(policies, roles, rbac, nil)

	ctx := context.Background()
	policy := &domainauth.Policy{
		Name:      "office-read",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"secrets/kv/*"},
		Actions:   []string{"read"},
		Conditions: map[string]any{
			"ip_cidr": []any{"10.0.0.0/8"},
		},
	}
	if err := svc.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("SavePolicy() = %v", err)
	}
	if err := svc.LoadIntoRBAC(ctx); err != nil {
		t.Fatalf("LoadIntoRBAC() = %v", err)
	}

	req := auth.RequestContext{ClientIP: "10.1.2.3"}
	if !rbac.Authorize([]string{"office-read"}, "secrets/kv/app", "read", req) {
		t.Fatal("expected conditioned policy to allow in CIDR")
	}
	req.ClientIP = "8.8.8.8"
	if rbac.Authorize([]string{"office-read"}, "secrets/kv/app", "read", req) {
		t.Fatal("expected conditioned policy to deny outside CIDR")
	}
}

func TestPolicyServiceRolesAndDelete(t *testing.T) {
	policies := memory.NewPolicyRepository()
	roles := memory.NewRoleRepository()
	rbac := auth.NewRBAC()
	svc := service.NewPolicyService(policies, roles, rbac, nil)
	ctx := context.Background()

	policy := &domainauth.Policy{
		Name:      "temp",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"secrets/kv/*"},
		Actions:   []string{"read"},
	}
	if err := svc.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("SavePolicy() = %v", err)
	}
	if err := svc.SaveRole(ctx, &domainauth.Role{Name: "app", Policies: []string{"temp"}}); err != nil {
		t.Fatalf("SaveRole() = %v", err)
	}

	list, err := svc.ListPolicies(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListPolicies() = %v, len=%d", err, len(list))
	}
	roleList, err := svc.ListRoles(ctx)
	if err != nil || len(roleList) != 1 {
		t.Fatalf("ListRoles() = %v, len=%d", err, len(roleList))
	}
	if err := svc.DeletePolicy(ctx, "temp"); err != nil {
		t.Fatalf("DeletePolicy() = %v", err)
	}
	if err := svc.DeleteRole(ctx, "app"); err != nil {
		t.Fatalf("DeleteRole() = %v", err)
	}
}
