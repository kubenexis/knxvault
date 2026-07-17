// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package leaseutil_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/engine/secrets/leaseutil"
	"github.com/kubenexis/knxvault/internal/repository/memory"
)

func TestCountActiveLeasesForRole(t *testing.T) {
	ctx := context.Background()
	if n, err := leaseutil.CountActiveLeasesForRole(ctx, nil, "database", "role"); err != nil || n != 0 {
		t.Fatalf("nil repo: n=%d err=%v", n, err)
	}

	repo := memory.NewLeaseRepository()
	now := time.Now().UTC()
	for _, l := range []*domainsecrets.Lease{
		{
			ID: "l1", Path: "database/creds/role/l1", RoleName: "role", Engine: "database",
			TTLSeconds: 3600, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Renewable: true,
		},
		{
			ID: "l2", Path: "database/creds/role/l2", RoleName: "role", Engine: "database",
			TTLSeconds: 1, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), Renewable: true,
		},
		{
			ID: "l3", Path: "database/creds/other/l3", RoleName: "other", Engine: "database",
			TTLSeconds: 3600, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Renewable: true,
		},
	} {
		if err := repo.Save(ctx, l); err != nil {
			t.Fatal(err)
		}
	}

	n, err := leaseutil.CountActiveLeasesForRole(ctx, repo, "database", "role")
	if err != nil || n != 1 {
		t.Fatalf("count=%d err=%v", n, err)
	}
}

func TestCheckMaxLeases(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewLeaseRepository()
	now := time.Now().UTC()
	for _, id := range []string{"a", "b"} {
		if err := repo.Save(ctx, &domainsecrets.Lease{
			ID: id, Path: "database/creds/role/" + id, RoleName: "role", Engine: "database",
			TTLSeconds: 3600, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Renewable: true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := leaseutil.CheckMaxLeases(ctx, repo, "database", "role", domainsecrets.LeaseTuning{}); err != nil {
		t.Fatalf("unlimited: %v", err)
	}
	if err := leaseutil.CheckMaxLeases(ctx, repo, "database", "role", domainsecrets.LeaseTuning{MaxLeases: 5}); err != nil {
		t.Fatalf("under quota: %v", err)
	}
	err := leaseutil.CheckMaxLeases(ctx, repo, "database", "role", domainsecrets.LeaseTuning{MaxLeases: 2})
	if err == nil {
		t.Fatal("expected max_leases error")
	}
	var kv *common.KNXVaultError
	if !errors.As(err, &kv) || kv.Code != common.ErrCodeForbidden {
		t.Fatalf("want forbidden, got %v", err)
	}
}
