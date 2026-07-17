// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestAuthorizePathUsesResourceLabels(t *testing.T) {
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name: "owner-a", Effect: domainauth.EffectAllow,
		Resources: []string{"secrets/kv/*"}, Actions: []string{"read"},
		Conditions: map[string]any{"owner_match": "team-a"},
	})
	svc := auth.NewService(auth.NewTokenStore(0), rbac, "")
	principal := auth.Principal{Subject: "user", Policies: []string{"owner-a"}}
	ctx := auth.WithRequestContext(context.Background(), auth.RequestContext{
		ResourceLabels: map[string]string{"owner": "team-b"},
	})
	if err := svc.AuthorizePath(ctx, principal, "secrets/kv/app/x", auth.CapRead); err == nil {
		t.Fatal("expected owner_match deny for team-b")
	}
	ctx = auth.WithRequestContext(context.Background(), auth.RequestContext{
		ResourceLabels: map[string]string{"owner": "team-a"},
	})
	if err := svc.AuthorizePath(ctx, principal, "secrets/kv/app/x", auth.CapRead); err != nil {
		t.Fatalf("expected allow for team-a owner: %v", err)
	}
}

func TestAuthorizePathUsesEnvironmentAndCluster(t *testing.T) {
	rbac := auth.NewRBAC()
	rbac.UpsertPolicy(domainauth.Policy{
		Name: "prod-only", Effect: domainauth.EffectAllow,
		Resources: []string{"secrets/kv/*"}, Actions: []string{"read"},
		Conditions: map[string]any{"environment": "prod", "cluster": "primary"},
	})
	svc := auth.NewService(auth.NewTokenStore(0), rbac, "")
	principal := auth.Principal{Subject: "user", Policies: []string{"prod-only"}}

	ctx := auth.WithRequestContext(context.Background(), auth.RequestContext{
		Environment: "staging",
		Cluster:     "primary",
	})
	if err := svc.AuthorizePath(ctx, principal, "secrets/kv/app/x", auth.CapRead); err == nil {
		t.Fatal("expected environment deny")
	}

	ctx = auth.WithRequestContext(context.Background(), auth.RequestContext{
		Environment: "prod",
		Cluster:     "primary",
		RequestPath: "/secrets/kv/app/x",
	})
	if err := svc.AuthorizePath(ctx, principal, "secrets/kv/app/x", auth.CapRead); err != nil {
		t.Fatalf("expected prod+primary allow: %v", err)
	}
}
