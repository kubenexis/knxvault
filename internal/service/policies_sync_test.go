package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestPolicyServiceSyncRBAC(t *testing.T) {
	ctx := context.Background()
	policies := memory.NewPolicyRepository()
	rbac := auth.NewRBAC()
	svc := service.NewPolicyService(policies, memory.NewRoleRepository(), rbac, nil)
	if err := svc.LoadIntoRBAC(ctx); err != nil {
		t.Fatalf("LoadIntoRBAC() = %v", err)
	}

	if err := policies.Save(ctx, &domainauth.Policy{
		Name:      "custom",
		Effect:    domainauth.EffectAllow,
		Resources: []string{"secrets/custom/*"},
		Actions:   []string{"read"},
	}); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	if rbac.Authorize([]string{"custom"}, "secrets/custom/app", "read", auth.RequestContext{}) {
		t.Fatal("local cache should not include policy written only to repository")
	}

	authSvc := auth.NewService(auth.NewTokenStore(time.Hour), rbac, "")
	authSvc.SetRBACSyncer(svc)
	if err := authSvc.Authorize(ctx, auth.Principal{Policies: []string{"custom"}}, "secrets/custom/app", "read"); err != nil {
		t.Fatalf("Authorize() after sync = %v", err)
	}
}
