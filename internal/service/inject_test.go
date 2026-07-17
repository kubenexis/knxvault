// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	auditsvc "github.com/kubenexis/knxvault/internal/audit"
	"github.com/kubenexis/knxvault/internal/inject"
	"github.com/kubenexis/knxvault/internal/repository"
	"github.com/kubenexis/knxvault/internal/repository/memory"
	"github.com/kubenexis/knxvault/internal/service"
)

func TestInjectServiceRecordCSIMount(t *testing.T) {
	auditRepo := memory.NewAuditRepository()
	auditSvc := auditsvc.NewService(auditRepo)
	svc := service.NewInjectService(inject.NewRenderer(nil), auditSvc)

	ctx := context.Background()
	if err := svc.RecordCSIMount(ctx, service.CSIMountAuditRequest{
		Role:           "app-sa",
		Namespace:      "prod",
		ServiceAccount: "my-app",
		PodName:        "my-app-1",
		Paths:          []string{"app/db"},
	}); err != nil {
		t.Fatalf("RecordCSIMount() = %v", err)
	}
	entries, err := auditRepo.List(ctx, repository.AuditListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(entries) != 1 || entries[0].Action != "csi.mount" {
		t.Fatalf("entries = %+v", entries)
	}
}
