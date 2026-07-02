package service_test

import (
	"context"
	"testing"
	"time"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
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
