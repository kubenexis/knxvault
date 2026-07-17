// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"fmt"
	"time"

	"github.com/kubenexis/knxvault/internal/acme/filestore"
)

// RenewPolicy controls when re-issue is required.
type RenewPolicy struct {
	// RenewBefore triggers renewal when notAfter - now <= RenewBefore.
	RenewBefore time.Duration
}

// DefaultRenewBefore is 30 days.
const DefaultRenewBefore = 720 * time.Hour

// NeedsRenew reports whether rec should be renewed at now.
func NeedsRenew(rec *filestore.CertRecord, now time.Time, policy RenewPolicy) bool {
	before := policy.RenewBefore
	if before <= 0 {
		before = DefaultRenewBefore
	}
	return rec.NeedsRenew(now, before)
}

// IssueFunc issues a certificate (usually Client.Issue).
type IssueFunc func(ctx context.Context, req OrderRequest) (*Result, error)

// RenewIfNeeded re-issues when the record is missing or within renew window.
// Returns (result, renewed, error). renewed is false when no work was needed.
func RenewIfNeeded(
	ctx context.Context,
	rec *filestore.CertRecord,
	now time.Time,
	policy RenewPolicy,
	req OrderRequest,
	issue IssueFunc,
) (*Result, bool, error) {
	if issue == nil {
		return nil, false, fmt.Errorf("issue function is nil")
	}
	if !NeedsRenew(rec, now, policy) {
		return nil, false, nil
	}
	res, err := issue(ctx, req)
	if err != nil {
		return nil, false, err
	}
	return res, true, nil
}
