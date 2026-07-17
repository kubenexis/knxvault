// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"strings"

	"github.com/kubenexis/knxvault/internal/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
	"github.com/kubenexis/knxvault/internal/tenant"
)

// scopeResourceName prefixes names (roles, CAs, etc.) when tenant mode is on (W32-04 / W53).
func scopeResourceName(ctx context.Context, tenantMode bool, name string) (string, error) {
	if !tenantMode {
		return name, nil
	}
	ns := tenant.FromContext(ctx)
	if ns == "" {
		return "", common.New(common.ErrCodeValidation, "tenant namespace required")
	}
	return tenant.ScopePath(ns, name, true), nil
}

func assertTenantAccess(ctx context.Context, tenantMode bool, scopedName string) error {
	if !tenantMode {
		return nil
	}
	ns := tenant.FromContext(ctx)
	if ns == "" {
		return common.New(common.ErrCodeValidation, "tenant namespace required")
	}
	if !tenant.ValidateAccess(ns, scopedName, true) {
		return common.New(common.ErrCodeNotFound, "resource not found")
	}
	return nil
}

// assertTenantLeaseAccess enforces lease ID tenant prefix when tenant mode is on (W64-01 / W76).
// Empty namespace fails closed (unlike soft-path jobs that may omit ns).
func assertTenantLeaseAccess(ctx context.Context, tenantMode bool, leaseID string) error {
	if !tenantMode {
		return nil
	}
	ns := tenant.FromContext(ctx)
	if ns == "" {
		if rc, ok := auth.RequestContextFromContext(ctx); ok {
			ns = strings.TrimSpace(rc.Namespace)
		}
	}
	if ns == "" {
		return common.New(common.ErrCodeForbidden, "tenant namespace required for lease access")
	}
	if !tenant.ValidateLeaseIDAccess(ns, leaseID, true) {
		return common.New(common.ErrCodeForbidden, "cross-tenant lease access denied")
	}
	return nil
}
