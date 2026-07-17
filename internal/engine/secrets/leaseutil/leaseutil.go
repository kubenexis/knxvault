// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package leaseutil

import (
	"context"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/common"
	domainsecrets "github.com/kubenexis/knxvault/internal/domain/secrets"
	"github.com/kubenexis/knxvault/internal/repository"
)

// CountActiveLeasesForRole returns active leases for engine+role.
func CountActiveLeasesForRole(ctx context.Context, leases repository.LeaseRepository, engine, role string) (int, error) {
	if leases == nil {
		return 0, nil
	}
	all, err := leases.List(ctx)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	count := 0
	for _, l := range all {
		if l.Engine == engine && l.RoleName == role && l.Active(now) {
			count++
		}
	}
	return count, nil
}

// CheckMaxLeases enforces per-role lease quotas (W42-07).
func CheckMaxLeases(ctx context.Context, leases repository.LeaseRepository, engine, role string, tuning domainsecrets.LeaseTuning) error {
	if tuning.MaxLeases <= 0 {
		return nil
	}
	count, err := CountActiveLeasesForRole(ctx, leases, engine, role)
	if err != nil {
		return err
	}
	if count >= tuning.MaxLeases {
		return common.New(common.ErrCodeForbidden, "max_leases quota exceeded for role")
	}
	return nil
}
