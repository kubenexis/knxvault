// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/auth"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestLeaseServiceGetAndList(t *testing.T) {
	leases := memory.NewLeaseRepository()
	now := time.Now().UTC()
	lease := &domainsecrets.Lease{
		ID:         "l_test",
		Path:       "database/creds/role/l_test",
		RoleName:   "role",
		Engine:     "database",
		TTLSeconds: 3600,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
		Renewable:  true,
	}
	if err := leases.Save(context.Background(), lease); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	svc := service.NewLeaseService(leases, nil, nil, auditsvc.NewService(memory.NewAuditRepository()))
	view, err := svc.Get(context.Background(), "l_test")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if view.ID != "l_test" || view.Engine != "database" {
		t.Fatalf("unexpected view: %+v", view)
	}

	list, err := svc.List(context.Background(), service.LeaseListFilter{Engine: "database"})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List() len = %d", len(list))
	}
}

func TestLeaseServiceListOffsetBeyondLength(t *testing.T) {
	leases := memory.NewLeaseRepository()
	now := time.Now().UTC()
	for i, id := range []string{"l_a", "l_b"} {
		lease := &domainsecrets.Lease{
			ID: id, Path: "database/creds/role/" + id, RoleName: "role",
			Engine: "database", TTLSeconds: 3600,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour), Renewable: true,
		}
		if err := leases.Save(context.Background(), lease); err != nil {
			t.Fatalf("Save() = %v", err)
		}
		_ = i
	}
	svc := service.NewLeaseService(leases, nil, nil, auditsvc.NewService(memory.NewAuditRepository()))
	list, err := svc.List(context.Background(), service.LeaseListFilter{Offset: 10})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty page, got %d leases", len(list))
	}
}

func TestLeaseServiceBulkRevokeWithoutEngineHook(t *testing.T) {
	// M-LEASE-1: unknown/unwired engines still mark leases revoked via repository.
	leases := memory.NewLeaseRepository()
	now := time.Now().UTC()
	lease := &domainsecrets.Lease{
		ID: "l_db", Engine: "database", RoleName: "role",
		Path: "database/creds/role/l_db", TTLSeconds: 3600,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), Renewable: true,
	}
	if err := leases.Save(context.Background(), lease); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	svc := service.NewLeaseService(leases, nil, nil, auditsvc.NewService(memory.NewAuditRepository()))
	res, err := svc.BulkRevoke(context.Background(), service.BulkRevokeRequest{Engine: "database"})
	if err != nil {
		t.Fatalf("BulkRevoke() = %v", err)
	}
	if res.Revoked != 1 {
		t.Fatalf("revoked=%d", res.Revoked)
	}
}

func TestLeaseServiceBulkRevokeRequiresSelector(t *testing.T) {
	leases := memory.NewLeaseRepository()
	svc := service.NewLeaseService(leases, nil, nil, auditsvc.NewService(memory.NewAuditRepository()))
	if _, err := svc.BulkRevoke(context.Background(), service.BulkRevokeRequest{}); err == nil {
		t.Fatal("expected empty bulk revoke to fail")
	}
}

func TestLeaseServiceRenewAndCascade(t *testing.T) {
	leases := memory.NewLeaseRepository()
	now := time.Now().UTC()
	lease := &domainsecrets.Lease{
		ID: "l1", Engine: "custom", RoleName: "r", Path: "custom/x",
		TTLSeconds: 60, CreatedAt: now, ExpiresAt: now.Add(time.Minute),
		Renewable: true, TokenID: "tokhash",
	}
	if err := leases.Save(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	svc := service.NewLeaseService(leases, nil, nil, auditsvc.NewService(memory.NewAuditRepository()))
	view, err := svc.Renew(context.Background(), "l1", 120)
	if err != nil || view.TTLSeconds != 120 {
		t.Fatalf("Renew: %v %+v", err, view)
	}
	n, err := svc.RevokeByTokenID(context.Background(), "tokhash")
	if err != nil || n != 1 {
		t.Fatalf("cascade: %v %d", err, n)
	}
}

func TestLeaseServiceTenantModeCrossTenantDenied(t *testing.T) {
	leases := memory.NewLeaseRepository()
	now := time.Now().UTC()
	for _, id := range []string{"ns-a.lease1", "ns-b.lease2"} {
		lease := &domainsecrets.Lease{
			ID: id, Engine: "database", RoleName: "role", Path: "database/creds/" + id,
			TTLSeconds: 3600, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Renewable: true,
		}
		if err := leases.Save(context.Background(), lease); err != nil {
			t.Fatal(err)
		}
	}
	svc := service.NewLeaseService(leases, nil, nil, auditsvc.NewService(memory.NewAuditRepository()))
	svc.SetTenantMode(true)

	ctxA := auth.WithRequestContext(context.Background(), auth.RequestContext{Namespace: "ns-a"})
	if _, err := svc.Get(ctxA, "ns-b.lease2"); err == nil {
		t.Fatal("expected cross-tenant Get denied")
	}
	if _, err := svc.Renew(ctxA, "ns-b.lease2", 60); err == nil {
		t.Fatal("expected cross-tenant Renew denied")
	}
	list, err := svc.List(ctxA, service.LeaseListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "ns-a.lease1" {
		t.Fatalf("list should be tenant-scoped, got %+v", list)
	}

	// Register prefixes lease ID with tenant namespace.
	reg := &domainsecrets.Lease{
		ID: "newlease", Engine: "database", RoleName: "role", Path: "database/creds/x",
		TTLSeconds: 60, CreatedAt: now, ExpiresAt: now.Add(time.Minute), Renewable: true,
	}
	if err := svc.Register(ctxA, reg); err != nil {
		t.Fatal(err)
	}
	if reg.ID != "ns-a.newlease" {
		t.Fatalf("Register should scope lease ID, got %s", reg.ID)
	}
}
